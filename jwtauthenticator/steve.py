import jwt

def verify_jwt_using_secret(json_web_token, secret, audience):

    if audience == "":
        audience = None
        
    try:
        return jwt.decode(json_web_token, secret, algorithms=['HS256','RS256'], audience=audience)
    except jwt.ExpiredSignatureError:
        print("Token has expired")
    except jwt.PyJWTError as ex:
        print("Token error - %s", ex)
    except Exception as ex:
        print("Could not decode token claims - %s", ex)
    raise Exception 


t = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ0b2tlbl90eXBlIjoiYWNjZXNzIiwiZXhwIjoxNTc1NDE4NDM3LCJqdGkiOiJhNGJjZDdmYjgzYzI0ZDIxYTBiMTA3ZWI0YjgzNjcxNCIsInVzZXJfaWQiOjExfQ.60pBE2tZ7-SZO28s9YJGdoKBXePCfT1vQmyCsJqOERA"
print(verify_jwt_using_secret(t, "q%ud#y^1v9#c3w&&77#&=e=$m)0c&s2o#z-iohe=mucml5i-3$", ""))