FRAUD SCANNER APP
=================

PROJECT STRUCTURE
-----------------
Fraud-Scanner-App/
  app.py
  requirements.txt
  render.yaml
  README.txt
  templates/
    index.html
  static/
    style.css
    script.js
    images/
      (place optional images here)

RUN LOCALLY
-----------
1. Install Python 3.10 or newer.
2. Open a terminal in this folder.
3. Run: pip install -r requirements.txt
4. Run: python app.py
5. Open: http://127.0.0.1:5000

DEPLOY TO RENDER
----------------
1. Upload the complete folder contents to a GitHub repository.
2. In Render, create a new Web Service and connect that repository.
3. Build command: pip install -r requirements.txt
4. Start command: gunicorn app:app
5. Add environment variable SECRET_KEY with a long random value.
6. Deploy.

IMPORTANT
---------
This is an educational, rule-based fraud-warning demo, not a definitive fraud detector.
The API stores users, scan history and reports in memory. This data is lost when the
server restarts or the hosting instance restarts. Use a persistent database and
additional security controls before real-world production use.
