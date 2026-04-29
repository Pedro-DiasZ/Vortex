import base64

def base64_encode(text):
    try:
        output = base64.b64encode(text.encode('utf-8')).decode('utf-8')
        return {"input": text, "output": output, "operation": "encode", "found": True}
    except Exception as e:
        return {"found": False, "status": str(e)}

def base64_decode(text):
    try:
        output = base64.b64decode(text.encode('utf-8')).decode('utf-8')
        return {"input": text, "output": output, "operation": "decode", "found": True}
    except Exception as e:
        return {"found": False, "status": str(e)}