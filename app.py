from flask import Flask, render_template_string
import pandas as pd

app = Flask(__name__)

@app.route('/')
def index():
    try:
        # CSV dosyasını okuyun
        df = pd.read_csv('anomalies.csv')
        print(df.head())  # DataFrame içeriğini terminalde yazdır

        # DataFrame'i HTML tabloya dönüştürün
        table_html = df.to_html(classes='table table-striped')
        
        # HTML template'i oluşturun
        html_template = '''
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Dashboard</title>
            <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
        </head>
        <body>
            <div class="container">
                <h1 class="mt-5">Detected Anomalies</h1>
                <div class="table-responsive">
                    {{ table_html | safe }}
                </div>
            </div>
        </body>
        </html>
        '''
        
        return render_template_string(html_template, table_html=table_html)
    except Exception as e:
        return f"An error occurred: {e}"

if __name__ == '__main__':
    app.run(debug=True)
