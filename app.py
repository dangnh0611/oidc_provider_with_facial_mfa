"""Application entry point."""
from auth_provider import create_app

app = create_app()

if __name__ == "__main__":

    app.run(host='0.0.0.0', port=5000, debug=True, ssl_context = ('cert.pem', 'key.pem') )
