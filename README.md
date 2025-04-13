# CommonOAuth
Simple OAuth helper service easily pluggable into other independent services


## To Run MainApp :
> 1) Go inside MainApp folder

> 2) python3 -m uvicorn main:app --host 0.0.0.0 --port 8008 --reload

## To Run AuthApp :
> 1) Go inside AuthApp folder

> 2) python3 -m uvicorn main:app --host 0.0.0.0 --port 8080 --reload


### Possible required installations :

> pip install fastapi uvicorn python-dotenv jinja2

> pip install authlib

> pip install PyJWT

> pip install itsdangerous

> pip install httpx


