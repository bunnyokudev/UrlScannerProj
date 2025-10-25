from flask import Flask, render_template
import os
import sys

# explicitly set folders (optional but helps)
app = Flask(__name__, template_folder='templates', static_folder='static')

@app.route('/')
def index():
    message = "Hello from Flask!"
    # diagnostic info
    print("=== RUNNING APP ===")
    print("cwd:", os.getcwd())
    print("app.root_path:", app.root_path)
    print("template_folder (resolves to):", os.path.join(app.root_path, app.template_folder))
    print("sys.executable:", sys.executable)
    return render_template("index.html")

if __name__ == "__main__":
    app.run(debug=True)
