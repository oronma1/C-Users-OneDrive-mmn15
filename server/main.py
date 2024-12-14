import server

# Default port
DEFAULT_PORT = 1256


if __name__ == '__main__':
    server = server.Server('localhost', DEFAULT_PORT)
    server.startServer()
