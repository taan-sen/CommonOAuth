from authlib.integrations.starlette_client import OAuth

oauth = OAuth()

def register_client(service_name, client_id, client_secret, **kwargs):
    oauth.register(
        name=service_name,
        client_id=client_id,
        client_secret=client_secret,
        **kwargs
    )
