from flask import Flask, render_template, jsonify
from detector import DoSDetector
import threading

app = Flask(__name__)
detector = DoSDetector()

@app.route('/', methods=['GET', 'POST'])
def index():
    return render_template('dashboard.html')

@app.route('/api/status')
def get_status():
    return jsonify(detector.get_status())

if __name__ == '__main__':
    print("Starting DoS Detector...")
    print("Note: Requires Administrator privileges to sniff packets.")
    
    # Start detection engine
    detector.start()
    
    app.run(debug=True, port=5000)
