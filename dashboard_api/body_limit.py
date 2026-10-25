"""Bound JSON request buffering before parsing, including chunked uploads."""
from starlette.responses import JSONResponse


class LabBodyLimit:
    def __init__(self, app, limit=131_072):
        self.app, self.limit = app, limit

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http' or not scope.get('path', '').startswith('/api/lab/'):
            return await self.app(scope, receive, send)
        chunks, size = [], 0
        limit = 2_000_000 if scope.get('path') == '/api/lab/verify-export' else self.limit
        while True:
            message = await receive()
            if message['type'] == 'http.disconnect':
                return
            size += len(message.get('body', b''))
            if size > limit:
                return await JSONResponse({'detail': f'Request exceeds {limit} byte limit.'}, status_code=413)(scope, receive, send)
            chunks.append(message)
            if not message.get('more_body', False):
                break
        async def replay():
            return chunks.pop(0) if chunks else await receive()
        return await self.app(scope, replay, send)
