import os
from flask import Flask, request, render_template, redirect, url_for, send_file, abort
from rq import Queue
from rq.job import Job
from worker import conn
from tasks import process_csv_task, process_crawl_task
from crawler import validate_start_url
import io

app = Flask(__name__)
q = Queue(connection=conn)

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        if request.form.get('mode') == 'crawl':
            try:
                start_url = validate_start_url(request.form.get('start_url', ''))
            except ValueError as exc:
                return render_template('index.html', error=str(exc)), 400
            job = q.enqueue(process_crawl_task, start_url, job_timeout=-1, result_ttl=3600)
            return redirect(url_for('status', job_id=job.get_id()))
        if 'file' not in request.files:
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            return redirect(request.url)
        if file:
            # Read file content as string
            try:
                content = file.read().decode('utf-8-sig') # Handle BOM
            except UnicodeDecodeError:
                try:
                    file.seek(0)
                    content = file.read().decode('utf-8')
                except UnicodeDecodeError:
                    # Try latin-1 fallback
                    file.seek(0)
                    content = file.read().decode('latin-1')
            
            job = q.enqueue(process_csv_task, content, result_ttl=3600)
            return redirect(url_for('status', job_id=job.get_id()))
    return render_template('index.html')

@app.route('/status/<job_id>')
def status(job_id):
    try:
        job = Job.fetch(job_id, connection=conn)
    except:
        return "Job not found", 404
    
    job_status = job.get_status()
    
    if job.is_finished:
        return render_template('status.html', job=job, status='finished', job_status=job_status)
    elif job.is_failed:
        return render_template('status.html', job=job, status='failed', job_status=job_status)
    else:
        logs = job.meta.get('logs', [])
        processed = job.meta.get('processed', 0)
        total = job.meta.get('total', 0)
        return render_template('status.html', job=job, status='processing', logs=logs, processed=processed, total=total, job_status=job_status)

@app.route('/download/<job_id>/<type>')
def download(job_id, type):
    try:
        job = Job.fetch(job_id, connection=conn)
    except:
        return "Job not found", 404
        
    if not job.is_finished:
        return "Job not finished", 400
        
    result = job.result
    if type == 'good':
        csv_data = result['good_csv']
        filename = 'good_urls.csv'
    elif type == 'bad':
        csv_data = result['bad_csv']
        filename = 'bad_urls.csv'
    elif type in ('redirected', 'crawl_errors') and f'{type}_csv' in result:
        csv_data = result[f'{type}_csv']
        filename = f'{type}.csv'
    else:
        return "Invalid type", 400
        
    return send_file(
        io.BytesIO(csv_data.encode('utf-8')),
        mimetype='text/csv',
        as_attachment=True,
        download_name=filename
    )

if __name__ == '__main__':
    app.run(debug=True)
