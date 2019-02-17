import logging
import select
import socket

import os
import mimetypes

import hashlib

class HTTPSession:
    def __init__(self, sock, addr):
        self.sock = sock
        self.addr = addr
        self.reset()

    def update(self, data):
        if len(data) == 0:
            self.__error = 1
            return
        self.__data += data
        while not self.__ready:
            if self.__status == 0:
                idx = self.__data.find(b'\r\n')
                if idx == -1: break
                self.__status_line = (self.__data[:idx]).decode()
                self.__data = self.__data[idx+2:]
                self.__status = 1
            elif self.__status == 1:
                idx = self.__data.find(b'\r\n')
                if idx == -1: break
                line = (self.__data[:idx]).decode()
                self.__data = self.__data[idx+2:]

                if len(line) != 0:
                    line = line.split(': ', 1)
                    if len(line) != 2:
                        self.__error = 2
                        break
                    self.__headers[line[0]] = line[1]
                else:
                    self.__status = 2
            elif self.__status == 2:
                if 'Content-Length' in self.__headers:
                    l = int(self.__headers['Content-Length'])
                    if len(self.__data) == l:
                        self.contentData = self.__data
                else:
                    self.contentData = None
                    self.__ready = True

    def reset(self):
        self.__ready = False
        self.__error = False

        self.__status = 0
        self.__data = b''

        self.__status_line = None
        self.__headers = {}
        self.contentData = None
    
    def close(self):
        self.__error = 3
    
    @property
    def isReady(self):
        return self.__ready
    
    @property
    def isError(self):
        errors = [None, '被动关闭', '协议错误', '主动关闭']
        return errors[self.__error]

    @property
    def status(self):
        assert(self.__ready)
        return self.__status_line.split(' ', 2)
    
    @property
    def headers(self):
        assert(self.__ready)
        return self.__headers

def response(sock, statusCode, keepAliveFlag, content=None, mimetype=None, etag=None):
    statusMap = {
        200: 'OK',
        304: 'Not Modify',
        404: 'Not Found',
    }
    sock.send('HTTP/1.1 {} {}\r\n'.format(statusCode, statusMap[statusCode]).encode())
    sock.send(b'Server: VerySimpleHTTPServer\r\n')
    sock.send('Connection: {}\r\n'.format('keep-alive' if keepAliveFlag else 'close').encode())
    if content:
        if etag:
            sock.send('Etag: {}\r\n'.format(etag).encode())
        sock.send('Content-Type: {}\r\n'.format(mimetype).encode())
        sock.send('Content-Length: {}\r\n'.format(len(content)).encode())
    sock.send(b'\r\n')
    if content:
        sock.send(content)

def handle(session):
    method, path, ver = session.status
    idx = path.find('?')
    if idx != -1:
        path = path[:idx]

    sock = session.sock
    if method in ('GET', ) and ver in ('HTTP/1.0', 'HTTP/1.1'):
        if path == '/': path = '/index.html'
        phy_path = os.path.join(os.path.dirname(__file__), 'html', path[1:])
        logging.info('客户端：{},请求路径：{}'.format(session.addr, phy_path))

        keepAliveFlag = (session.headers.get('Connection') == 'keep-alive')
        fileExistsFlag = os.path.exists(phy_path)
        if fileExistsFlag:
            fileData = open(phy_path, 'rb').read()
            fileMimeType = mimetypes.guess_type(phy_path)[0]
            etag = hashlib.sha1(fileData).hexdigest()[:10]
            etagMatchFlag = (session.headers.get('If-None-Match') == etag)
        else:
            etagMatchFlag = False

        try:
            if fileExistsFlag and not etagMatchFlag:
                response(sock, 200, keepAliveFlag, fileData, fileMimeType, etag)
            elif etagMatchFlag:
                response(sock, 304, keepAliveFlag)
            else:
                errorPagePath = os.path.join(os.path.dirname(__file__), '404.html')
                response(sock, 404, keepAliveFlag, open(errorPagePath, 'rb').read(), 'text/html')
            if keepAliveFlag:
                session.reset()
            else:
                session.close()
        except IOError as e:
            logging.warn('socket错误：{}'.format(e))
            session.close()
    else:
        logging.info('客户端：{},不支持的方法协议组合：{}'.format(session.addr, (method, ver)))
        session.close()

if __name__ == '__main__':
    logging.basicConfig(
        level=logging.DEBUG,
        filename='server.log'
    )
    mimetypes.init()
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
    server.setblocking(False)
    server.bind(('', 8080))
    server.listen(10)
    logging.info('初始化系统完成，http服务监听在8080端口上')

    sessions = {}
    while True:
        rs, _, _ = select.select([server.fileno()] + list(sessions.keys()), [], [])
        for sfd in rs:
            if sfd == server.fileno():
                conn, addr = server.accept()
                conn.setblocking(False)
                sessions[conn.fileno()] = HTTPSession(conn, addr)
                logging.info('新连接：{}'.format(addr))
            else:
                session = sessions[sfd]
                buf = session.sock.recv(4096)
                session.update(buf)

                if session.isReady:
                    handle(session)
                if session.isError:
                    session.sock.close()
                    del sessions[sfd]
                    logging.debug('关闭连接:{}, {}'.format(session.addr, session.isError))
