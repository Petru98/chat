#!/usr/bin/python3

import datetime                          # For timestamping messages
import tkinter.messagebox as messagebox  # Quit dialouge box
import tkinter as tk                     # GUI
import socket                            # Socket connections
import threading                         # Running multiple functions at once
import requests
import enum
import copy
from crypt import RSA

KEY_SIZE = 2048

def runAsync(proc, *args, **kwargs):
    thread = threading.Thread(target = proc, args = args, kwargs = kwargs, daemon = True)
    thread.start()
    return thread

@enum.unique
class MessageTypes(enum.IntEnum):
    def _generate_next_value_(name, start, count, last_values):
        if len(last_values) == 0:
            return 0
        return last_values[-1] + 1

    NORMAL      = enum.auto()
    DISCONNECT  = enum.auto()
    FILE        = enum.auto()
    SERVER      = enum.auto()
    NAME_IN_USE = enum.auto()
    KICK        = enum.auto()

class NameInUseError(Exception):
    def __init__(self):
        pass
class DataReceiveError(ConnectionError):
    def __init__(self, size, data):
        self.size = size
        self.data = data

    def __str__(self):
        return "Received {}/{}: {}".format(self.size, len(self.data), self.data)
class PortBindError(ConnectionError):
    def __init__(self, port):
        self.port = port

    def __str__(self):
        return "Port {}".format(self.port)
class PortListenError(ConnectionError):
    def __init__(self, port):
        self.port = port

    def __str__(self):
        return "Port {}".format(self.port)

class ClientInfo(object):
    def __init__(self):
        self.socket = None
        self.host = None
        self.port = None
        self.name = None
        self.id = None
        self.key = None

class ClientList(object):
    class Iterator(object):
        def __init__(self, client_list):
            self.client_list = client_list
            self.current = 0

        def __iter__(self):
            return self

        def __next__(self):
            if self.current >= len(self.client_list):
                raise StopIteration()
            client = self.client_list[self.current]
            self.current += 1
            return client


    def __init__(self):
        self._list = []

    def __len__(self):
        return len(self._list)

    def __getitem__(self, key):
        return self._list[key]

    def __iter__(self):
        return ClientList.Iterator(self)

    def __delattr__(self, client):
        self.erase(client)

    def insert(self, client):
        client.id = len(self._list)
        self._list.append(client)
        return copy.copy(client.id)

    def erase(self, client):
        del self._list[client.id]
        n = len(self._list)
        i = copy.copy(client.id)
        while i < n:
            self._list[i].id = i
            i += 1
        client.id = None

    def clear(self):
        self._list.clear()


class Client(object):
    class ServerInfo(object):
        def __init__(self):
            self.socket = None
            self.host = None
            self.port = None
            self.key = None

    def __init__(self, chat):
        self.chat = chat
        self.name = None
        self.key = RSA.generateCipher(KEY_SIZE)
        self.server = Client.ServerInfo()

        self.connectionMutex = threading.RLock()

    def go_offline(self):
        wasConnected = False

        with self.connectionMutex:
            if self.server.socket != None:
                wasConnected = True
                self.chat.on_offline()
                self.server.socket.close()
                self.server.socket = None
                self.server.host = None
                self.server.port = None
                self.server.key = None

        return wasConnected

    # HANDLERS
    def handle_normal_message(self):
        name = self.receive_string()
        message = self.receive_string()
        self.chat.printMessage(name, message)

    def handle_server_message(self):
        message = self.receive_string()
        self.chat.printServerMessage(message)

    def handle_disconnect_message(self):
        self.chat.printServerMessage("Server closed")
        self.disconnect()

    def handle_kick_message(self):
        self.chat.printServerMessage("You have been kicked")
        self.go_offline()

    def handle_file_message(self):
        self.chat.printError("messageType == MessageTypes.FILE not supported")

    def handle_unknown_message(self):
        self.chat.printError("Unknown message type from server")

    messageHandlers = {
                          MessageTypes.NORMAL      : handle_normal_message,
                          MessageTypes.SERVER      : handle_server_message,
                          MessageTypes.DISCONNECT  : handle_disconnect_message,
                          MessageTypes.KICK        : handle_kick_message,
                          MessageTypes.FILE        : handle_file_message
                      }

    def handle_server_messages(self):
        while self.server.socket != None:
            try:
                messageType = self.receiveByte()
                Client.messageHandlers.get(messageType, handle_unknown_message)(self)

            except (ConnectionResetError, OSError):
                if self.go_offline():
                    self.chat.printError("Connection to server lost")

    # CALLED BY CHAT
    def connect(self, host, port, name):
        with self.connectionMutex:
            serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            try:
                serverSocket.connect((host, port))
                self.send_string(name)
                if self.receive_byte() == 0:
                    raise NameInUseError()

                self.send_binary(self.key.publickey().exportKey("DER"))
                serverKey = RSA.createCipherFromExportedKey(self.receive_binary())

                self.disconnect()
                self.name = name
                self.server.socket = serverSocket
                self.server.host = host
                self.server.port = port
                self.server.key = serverKey

                runAsync(self.handle_server_messages)

            except:
                serverSocket.close()
                raise

    def disconnect(self):
        wasConnected = False

        with self.connectionMutex:
            if self.server.socket != None:
                wasConnected = True

                try:
                    self.send_byte(MessageTypes.DISCONNECT)
                except:
                    pass
                try:
                    self.server.socket.shutdown(socket.SHUT_RDWR)
                except:
                    pass

                self.go_offline()

        return wasConnected

    def on_exit(self):
        self.disconnect()


    def send_message(self, message):
        self.send_byte(MessageTypes.NORMAL)
        self.send_string(message)

    # SEND
    def send(self, data):
        with self.connectionMutex:
            if self.server.socket == None:
                raise ConnectionResetError()
            self.server.socket.sendall(data)

    def send_int(self, integer, size = 4, signed = False):
        self.send(integer.to_bytes(size, byteorder = "big", signed = signed))

    def send_byte(self, byte, signed = False):
        self.send_int(byte, size = 1, signed = signed)

    def send_binary(self, data):
        data = self.on_send(data)
        with self.connectionMutex:
            self.send_int(len(data))
            self.send(data)

    def send_string(self, message):
        self.send_binary(message.encode())

    # RECEIVE
    def receive(self, size):
        buffer = b""

        while size > 0:
            packet = self.server.socket.recv(size)
            if not packet:
                raise DataReceiveError(size, buffer)
            buffer += packet
            size -= len(packet)

        return data

    def receive_into(self, buffer, size = None):
        view = memoryview(buffer)

        while len(buffer) < size:
            received = self.server.socket.recv_into(view, size)
            if not received:
                raise DataReceiveError(size, buffer)
            view = view[received :]
            size -= received

        return buffer

    def receive_int(self, size = 4, signed = False):
        return int.from_bytes(self.receive(size), byteorder = "big", signed = signed)

    def receive_byte(self, signed = False):
        return self.receive_int(size = 1, signed = signed)

    def receive_binary(self):
        size = self.receive_int()
        message = bytearray(size)
        self.receive_into(message, size)
        message = self.on_receive(bytes(message))
        return message

    def receive_string(self):
        return self.receive_binary().decode()

    # CALLBACK
    def on_send(self, data):
        return data

    def on_receive(self, data):
        return data

class Server(object):
    class ClientInfo(object):
        def __init__(self):
            self.socket = None
            self.host = None
            self.port = None
            self.name = None
            self.id = None
            self.key = None

    class ClientList(object):
        class Iterator(object):
            def __init__(self, client_list):
                self.client_list = client_list
                self.current = 0

            def __iter__(self):
                return self

            def __next__(self):
                if self.current >= len(self.client_list):
                    raise StopIteration()
                client = self.client_list[self.current]
                self.current += 1
                return client


        def __init__(self):
            self._list = []

        def __len__(self):
            return len(self._list)

        def __getitem__(self, key):
            return self._list[key]

        def __iter__(self):
            return ClientList.Iterator(self)

        def __delattr__(self, client):
            self.erase(client)

        def insert(self, client):
            client.id = len(self._list)
            self._list.append(client)
            return copy.copy(client.id)

        def erase(self, client):
            del self._list[client.id]
            n = len(self._list)
            i = copy.copy(client.id)
            while i < n:
                self._list[i].id = i
                i += 1
            client.id = None

        def clear(self):
            self._list.clear()


    def __init__(self, chat):
        self.chat = chat
        self.name = None
        self.host = None
        self.port = None
        self.key = None
        self.socket = None
        self.chatLogFile = None
        self.clients = Server.ClientList()

        self.connectionMutex = threading.RLock()

    def go_offline(self):
        self.connectionMutex.acquire()
        wasOpen = False

        if self.socket != None:
            wasOpen = True
            self.chat.on_offline()
            self.socket.close()
            self.socket = None
            self.host = None
            self.port = None
            self.clients.clear()

        self.connectionMutex.release()
        return wasOpen

    # HANDLERS
    def listen(self):
        client = ClientInfo()

        while self.socket != None:
            try:
                client.__init__()
                client.socket, (client.host, client.port) = self.socket.accept()

            except OSError:
                with self.connectionMutex:
                    if self.socket != None:
                        self.chat.printError("OSError raised while waiting for new clients (please restart the server)")
                return

            with self.connectionMutex:
                ip_port = "{}:{}".format(client.host, client.port)
                self.chat.printInfo("Accepted connection from: {}".format(ip_port))

                try:
                    client.name = self.receive_string_from(client)

                    if any(client.name == c.name for c in self.clients):
                        self.sendByteTo(client.socket, 0)
                        client.socket.close()
                        self.printInfo("Client {} tried connecting with '{}' - already in use".format(ip_port, client.name))
                        continue

                    self.sendByteTo(client.socket, 1)
                    client.key = RSA.createCipherFromExportedKey(self.receive_binary_from(client.socket))
                    self.send_binary_to(client, self.key.publickey().exportKey("DER"))

                    client.id = self.clients.insert(copy.copy(client))

                    self.send_server_message_to(client, "Your connection was successful!\n")
                    self.printInfo("Client {} ({}) connection successful".format(client.name, ip_port))
                    self.send_server_message("{} joined".format(client.name))

                    run_async(self.handle_client, self.clients[client.id])

                except (ConnectionResetError, ConnectionAbortedError, OSError):
                    if client.name == None:
                        self.printInfo("Lost connection with unknown client ({}) before full connection".format(ip_port))
                    else:
                        self.clients.erase(client)
                        self.propagateServerMessage(client.socket, "Client {} disconnected".format(client.name))
                        self.printInfo("Client {} ({}) disconnected".format(client.name, ip_port))

                    client.socket.close()

    def handle_normal_message(self, sender):
        message = self.receive_string_from(sender)
        self.chat.printMessage(sender.name, message)
        self.propagate_message(sender, message)

    def handle_server_message(self, sender):
        message = self.receive_string_from(sender)
        self.chat.printServerMessage(message)
        self.propagate_server_message(sender, message)

    def handle_disconnect_message(self, sender):
        with self.connectionMutex:
            self.chat.printServerMessage("{} ({}:{}) disconnected".format(sender.name, sender.host, sender.port))
            self.propagate_server_message("{} disconnected".format(sender.name))
            sender.socket.close()
            self.clients.erase(sender)
            sender.__init__()

    def handle_kick_message(self, sender):
        self.chat.printError("{} ({}:{}) tried to kick someone (clients can't kick)".format(sender.name, sender.host, sender.port))

    def handle_file_message(self, sender):
        self.chat.printError("From {} ({}:{}): messageType == MessageTypes.FILE not supported".format(sender.name, sender.host, sender.port))

    def handle_unknown_message(self, sender):
        self.chat.printError("Unknown message type from client {} ({}:{})".format(sender.name, sender.host, sender.port))

    messageHandlers = {
                          MessageTypes.NORMAL      : handle_normal_message,
                          MessageTypes.SERVER      : handle_server_message,
                          MessageTypes.DISCONNECT  : handle_disconnect_message,
                          MessageTypes.KICK        : handle_kick_message,
                          MessageTypes.FILE        : handle_file_message
                      }

    def handle_client(self, client):
        while client != None:
            try:
                messageType = self.receive_byte_from(client)
                Server.messageHandlers.get(messageType, handle_unknown_message)(self, client)

            except (ConnectionResetError, ConnectionAbortedError, OSError) as e:
                with self.connectionMutex:
                    if client.socket != None:
                        client.socket.close()
                        self.clients.erase(client)
                        client = None

                        self.propagateServerMessage("Lost connection with {}".format(client.name))
                        self.printInfo("Lost connection with {} ({}:{})".format(client.name, client.host, client.port))

    # CALLED BY CHAT
    def open(self, host, port, name, log):
        with self.connectionMutex:
            serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            try:
                serverSocket.bind((host, port))
            except OSError:
                serverSocket.close()
                raise PortBindError(port)

            try:
                serverSocket.listen(128)
            except:
                serverSocket.close()
                raise PortListenError(port)

            if log:
                try:
                    self.chatLogFile = open("chatlog.txt", "w")
                except IOError:
                    pass

            self.close()
            self.socket = serverSocket
            self.host = host
            self.port = port
            self.name = name

            run_async(self.listen)

        return bool(log) == bool(self.chatLogFile)

    def close(self):
        wasOpen = False

        with self.connectionMutex:
            if self.server.socket != None:
                wasOpen = True

                for client in self.clients:
                    try:
                        self.send_byte_to(client.socket, MessageTypes.DISCONNECT)
                        client.socket.shutdown(socket.SHUT_RDWR)
                        client.socket.close()
                    except:
                        pass

                self.go_offline()

        return wasOpen

    def on_exit(self):
        self.close()


    def send_message(self, message):
        with self.connectionMutex:
            for client in self.clients:
                self.send_message_to(client, self.name, message)

    # SPECIAL SEND
    def send_server_message(self, message):
        with self.connectionMutex:
            for client in self.clients:
                self.send_server_message_to(client, message)

    def propagate_message(self, sender, message):
        with self.connectionMutex:
            for client in self.clients:
                if client.id != sender.id:
                    self.send_message_to(client, sender.name, message)

    def propagate_server_message(self, sender, message):
        with self.connectionMutex:
            for client in self.clients:
                if client.id != sender.id:
                    self.send_server_message_to(client, message)

    # SPECIAL SEND TO
    def send_message_to(self, client, name, message):
        with self.connectionMutex:
            self.send_byte_to(client, MessageTypes.NORMAL)
            self.send_string_to(client, name)
            self.send_string_to(client, message)

    def send_server_message_to(self, client, message):
        with self.connectionMutex:
            self.send_byte_to(client, MessageTypes.SERVER)
            self.send_string_to(client, message)

    # SEND
    def send(self, data):
        with self.connectionMutex:
            for client in self.clients:
                client.socket.sendall(data)

    def send_int(self, integer, size = 4, signed = False):
        self.send(integer.to_bytes(size, byteorder = "big", signed = signed))

    def send_byte(self, byte, signed = False):
        self.send_int(byte, size = 1, signed = signed)

    def send_binary(self, data):
        with self.connectionMutex:
            for client in self.clients:
                temp_data = self.on_send(data, client)
                self.send_int_to(client, len(temp_data))
                self.send(client, temp_data)

    def send_string(self, message):
        self.send_binary(message.encode())

    # SEND TO
    def send_to(self, client, data):
        with self.connectionMutex:
            client.socket.sendall(data)

    def send_int_to(self, client, integer, size = 4, signed = False):
        self.send_to(client, integer.to_bytes(size, byteorder = "big", signed = signed))

    def send_byte_to(self, client, byte, signed = False):
        self.send_int_to(client, byte, size = 1, signed = signed)

    def send_binary_to(self, client, message):
        message = self.on_send(message, client)
        with self.connectionMutex:
            self.send_int_to(client, len(message))
            self.send_to(client, message)

    def send_string_to(self, client, message):
        self.send_binary_to(client, message.encode())

    # RECEIVE
    def receive_from(self, client, size):
        buffer = b""

        while size > 0:
            packet = client.socket.recv(size)
            if not packet:
                raise DataReceiveError(size, buffer)
            buffer += packet
            size -= len(packet)

        return data

    def receive_into_from(self, client, buffer, size = None):
        view = memoryview(buffer)

        while len(buffer) < size:
            received = client.socket.recv_into(view, size)
            if not received:
                raise DataReceiveError(size, buffer)
            view = view[received :]
            size -= received

        return buffer

    def receive_int_from(self, client, size = 4, signed = False):
        return int.from_bytes(self.receive_from(client, size), byteorder = "big", signed = signed)

    def receive_byte_from(self, client, signed = False):
        return self.receive_int_from(client, size = 1, signed = signed)

    def receive_binary_from(self, client):
        size = self.receive_int_from(client)
        message = bytearray(size)
        self.receive_into_from(client, message, size)
        message = self.on_receive(bytes(message), client)
        return message

    def receive_string_from(self, client):
        return self.receive_binary_from(client).decode()

    # CALLBACK
    def on_send(self, data, client):
        return data

    def on_receive(self, data, client):
        return data


class ChatWindow(tk.Tk):
    TYPE_NONE = None
    TYPE_CLIENT = 0
    SERVER = 1

    def __init__(self, *args, **kwargs):
        tk.Tk.__init__(self, *args, **kwargs)
        self.type = ChatWindow.TYPE_NONE
        self.geometry("775x655")
        self.title("Chat")

        self.socket = None
        self.host = None
        self.port = None
        self.name = None
        self.chatlogfile = None

        self.socket_mutex = threading.RLock()
        self.print_mutex = threading.RLock()
        self.clients = ClientList()
        self.key = RSA.generateCipher(KEY_SIZE)
        self.protocol("WM_DELETE_WINDOW", self.onClose)

        # Grid
        self.grid_rowconfigure(0, weight = 1)
        self.grid_rowconfigure(1, weight = 0)
        self.grid_rowconfigure(2, weight = 0)
        self.grid_columnconfigure(0, weight = 1)
        self.grid_columnconfigure(1, weight = 0)

        #  create a Frame for the Text and Scrollbar
        self.txt_frm = tk.Frame(self, width = 775, height = 600)
        self.txt_frm.grid_propagate(False)
        self.txt_frm.grid(row = 0, column = 0, sticky = "nsew", columnspan = 2)
        self.txt_frm.grid_rowconfigure(0, weight = 1)
        self.txt_frm.grid_columnconfigure(0, weight = 1)

        self.message_area = tk.Text(self.txt_frm, borderwidth = 3, relief = "sunken", state = "disabled")
        self.message_area.config(font = ("consolas", 10), undo = True, wrap = 'word')
        self.message_area.grid(row = 0, column = 0, sticky = "nsew", padx = 2, pady = 2)

        self.scrollb = tk.Scrollbar(self.txt_frm, command = self.message_area.yview)
        self.scrollb.grid(row = 0, column = 1, sticky = "nse")
        self.message_area["yscrollcommand"] = self.scrollb.set

        # Entries
        self.msg_entry = tk.Entry(self, width = 20)
        self.msg_entry.grid(row = 1, column = 0, sticky = "nsew", padx = 2, pady = 1)

        self.bind("<Return>", lambda event: self.sendMessageFromBox())
        self.btn_send = tk.Button(self, text = "Send", command = self.sendMessageFromBox, width = 20)
        self.btn_send.grid(row = 1, column = 1, sticky = "ew", padx = 2, pady = 1)

        # Add colours to message_area
        self.message_area.tag_configure("red", foreground = "red")
        self.message_area.tag_configure("blue", foreground = "blue")
        self.message_area.tag_configure("purple", foreground = "purple")
        self.message_area.tag_configure("server", foreground = "purple")
        self.message_area.tag_configure("own_message", foreground = "blue")

        # Menu
        menubar = tk.Menu(self)

        server_menu = tk.Menu(menubar, tearoff = 0)
        server_menu.add_command(label = "Create", command = self.createServerFromPopup)
        server_menu.add_command(label = "Close", command = self.closeServer)
        server_menu.add_command(label = "Info", command = self.printServerInfo)

        client_menu = tk.Menu(menubar, tearoff = 0)
        client_menu.add_command(label = "Connect", command = self.connectToServerFromPopup)
        client_menu.add_command(label = "Disconnect", command = self.disconnectFromServer)

        menubar.add_cascade(label = "Server", menu = server_menu)
        menubar.add_cascade(label = "Client", menu = client_menu)
        menubar.add_command(label = "Clear", command = self.clear)

        self["menu"] = menubar

        # Postprocessing
        self.disable()

    # SERVER
    def createServerFromPopup(self):
        popup = LaunchWindowServer(self)
        popup.mainloop()

    def createServer(self, host, port, name, log):
        self.closeServer()
        self.disconnectFromServer()

        self.socket_mutex.acquire()
        self.print_mutex.acquire()
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            self.socket.bind((host, port))
        except OSError:
            self.closeSocket()
            self.printError("Unable to bind to port {}".format(port))
        else:
            self.printInfo("Socket bound")

            try:
                self.socket.listen()
            except TypeError: # Py versions < 3.5
                try:
                    self.socket.listen(64)
                except:
                    self.closeSocket()
                    self.printError("Unable to listen to port")
                    self.socket_mutex.release()
                    self.print_mutex.release()
                    return

            self.printInfo("Socket listening")

            if self.chatlogfile != None:
                self.chatlogfile = open("chatlog.txt", "w")
                self.printInfo("chatlog.txt ready to write")

            self.host = host
            self.port = port
            self.name = name

            client_checking_thrd = threading.Thread(target = self.listen)
            client_checking_thrd.daemon = True
            client_checking_thrd.start()
            self.printInfo("Server started")
            self.printServerInfo()

            self.title("Server | {}:{}".format(host, port))
            self.type = ChatWindow.SERVER
            self.enable()

        self.socket_mutex.release()
        self.print_mutex.release()

    def closeServer(self):
        if self.type == ChatWindow.SERVER:
            self.socket_mutex.acquire()
            self.print_mutex.acquire()

            for client in self.clients:
                client.socket.close()
            self.clients.clear()

            self.goOffline()
            self.printInfo("Server Stopped")
            if self.chatlogfile != None:
                self.chatlogfile.close()
                self.chatlogfile = None

            self.socket_mutex.release()
            self.print_mutex.release()

    def propagateServerMessage(self, message):
        self.socket_mutex.acquire()

        for client in self.clients:
            try:
                self.sendByteTo(client.socket, MessageTypes.SERVER)
                self.sendStringMessageTo(client.socket, message)
            except (BrokenPipeError, OSError):
                client.socket.close()
                self.clients.erase(client)

        self.socket_mutex.release()

    def propagateMessage(self, sender, message):
        self.socket_mutex.acquire()

        if sender == None:
            sender = ClientInfo()
            sender.name = self.name
            sender.id = None

        for client in self.clients:
            if client.id != sender.id:
                try:
                    self.sendByteTo(client.socket, MessageTypes.NORMAL)
                    self.sendStringMessageTo(client.socket, sender.name)
                    self.sendStringMessageTo(client.socket, message)
                except (BrokenPipeError, OSError):
                    client.socket.close()
                    self.clients.erase(client)

        self.socket_mutex.release()

    def kick(self, client_name):
        self.socket_mutex.acquire()
        self.print_mutex.acquire()

        name_id_map = {c.name: c.id for c in self.clients}

        try:
            client = self.clients[name_id_map[client_name]]
            self.sendByteTo(client, MessageTypes.KICK)
            client.socket.close()
            self.clients.erase(client)

            kick_msg = "{} was kicked from the server".format(client_name)
            self.printInfo(kick_msg)
            self.propagateServerMessage(kick_msg)

        except KeyError:
            self.printError("Invalid name {}".format(client_name))

        self.socket_mutex.release()
        self.print_mutex.release()

    def listen(self):
        client = ClientInfo()

        while self.socket != None:
            try:
                client.__init__()
                client.socket, (client.host, client.port) = self.socket.accept()

            except OSError:
                self.socket_mutex.acquire()
                if self.socket != None:
                    self.printError("OSError raised while waiting for new client connections")
                    self.closeServer()
                self.socket_mutex.release()

            else:
                self.socket_mutex.acquire()
                self.print_mutex.acquire()

                ip_port = "{}:{}".format(client.host, client.port)
                self.printInfo("Accepted connection from: {}".format(ip_port))

                try:
                    client.key = self.receiveMessageFrom(client.socket)
                    client.key = RSA.createCipherFromExportedKey(client.key)

                    client.name = self.receiveStringMessageFrom(client.socket)

                    if any(client.name == c.name for c in self.clients):
                        self.sendByteTo(client.socket, MessageTypes.NAME_IN_USE)
                        client.socket.close()
                        self.printInfo("Client {} tried connecting with '{}' - already in use".format(ip_port, client.name))
                    else:
                        client.id = self.clients.insert(copy.copy(client))

                        message = "Your connection was successful!\n"
                        self.sendByteTo(client.socket, MessageTypes.SERVER)
                        self.sendStringMessageTo(client.socket, message)

                        self.printInfo("Client {} ({}) connection successful".format(client.name, ip_port))
                        self.propagateServerMessage("{} joined".format(client.name))

                except (ConnectionResetError, ConnectionAbortedError, OSError):
                    if client.name == None:
                        self.printInfo("Unknown client ({}) disconnected before full connection".format(ip_port))
                    else:
                        self.clients.erase(client)
                        self.propagateServerMessage(client.socket, "Client {} disconnected".format(client.name))
                        self.printInfo("Client {} ({}) disconnected".format(client.name, ip_port))

                    client.socket.close()

                else:
                    if client.id != None:
                        client_handler_thread = threading.Thread(target = self.handleClient, args = (self.clients[client.id],))
                        client_handler_thread.daemon = True
                        client_handler_thread.start()

                    self.print_mutex.release()
                    self.socket_mutex.release()

    def handleClient(self, client):
        while client != None:
            try:
                message = self.receiveStringMessageFrom(client.socket)
                self.printMessage(client.name, message)
                self.propagateMessage(client, message)

            except (ConnectionResetError, ConnectionAbortedError, OSError) as e:
                self.socket_mutex.acquire()

                try:
                    self.clients.erase(client)
                    client.socket.close()
                except (KeyError, IndexError):
                    pass
                else:
                    self.propagateServerMessage("Client {} disconnected".format(client.name))
                    self.printInfo("Client {} ({}:{}) disconnected".format(client.name, client.host, client.port))

                client = None
                self.socket_mutex.release()

    # CLIENT
    def connectToServerFromPopup(self):
        popup = LaunchWindowClient(self)
        popup.mainloop()

    def connectToServer(self, host, port, name):
        self.closeServer()
        self.disconnectFromServer()

        self.host = host
        self.port = port
        self.name = name

        # Threading so the GUI doesn't freeze when connecting
        t = threading.Thread(target = self.connectToServerAsync)
        t.daemon = True
        t.start()

    def connectToServerAsync(self):
        self.socket_mutex.acquire()
        self.print_mutex.acquire()

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            self.socket.connect((self.host, self.port))

        except OSError:
            self.printError("Attempted connection to an unreachable network")
            self.printError("[Debug Info] IP:{}, Port:{}, Name:{}".format(self.host, self.port, self.name))
            self.closeSocket()

        except ConnectionRefusedError:
            self.printError("Connection refused")
            self.printError("[Debug Info] IP:{}, Port:{}, Name:{}".format(self.host, self.port, self.name))
            self.closeSocket()

        else:
            self.printInfo("Connected to server")
            self.sendMessage(self.key.publickey().exportKey("DER"))
            self.sendStringMessage(self.name)
            self.printInfo("Name sent")

            self.message_handler = threading.Thread(target = self.handleServerMessages)
            self.message_handler.daemon = True
            self.message_handler.start()

            self.title("Client | Connected to {}:{}".format(self.host, self.port))
            self.type = ChatWindow.TYPE_CLIENT
            self.enable()

        self.socket_mutex.release()
        self.print_mutex.release()

    def disconnectFromServer(self):
        if self.type == ChatWindow.TYPE_CLIENT:
            self.goOffline()
            self.printInfo("Disconnected")

    def handleServerMessages(self):
        while self.socket != None:
            try:
                message_type = self.receiveByte()

                if message_type == MessageTypes.NORMAL:
                    name = self.receiveStringMessage()
                    message = self.receiveStringMessage()

                    self.printMessage(name, message)

                elif message_type == MessageTypes.SERVER:
                    message = self.receiveStringMessage()

                    self.printServerMessage(message)

                elif message_type == MessageTypes.KICK:
                    self.printServerMessage("You have been kicked")
                    raise ConnectionResetError

                elif message_type == MessageTypes.NAME_IN_USE:
                    self.printServerMessage("Name already in use")
                    raise ConnectionResetError

                elif message_type == MessageTypes.FILE:
                    self.printError("message_type == MessageTypes.FILE is not supported")

                else:
                    self.printError("Unknown message type from server: {}".format(message_type))
                    self.socket.recv(KEY_SIZE)

            except (ConnectionResetError, OSError):
                self.socket_mutex.acquire()
                if self.socket != None:
                    self.goOffline()
                    self.printError("Connection to server lost")
                self.socket_mutex.release()

    # SHARED
    def write(self, text, tag = ""):
        self.print_mutex.acquire()

        if self.chatlogfile != None:
            self.chatlogfile.write(text)

        self.message_area.configure(state = "normal")
        self.message_area.insert(tk.END, text, tag)
        self.message_area.configure(state = "disabled")
        self.message_area.see(tk.END)

        self.print_mutex.release()

    def print(self, text, tag = ""):
        self.write("{} | {}".format(datetime.datetime.now().strftime("%H:%M"), text), tag)
    def printLine(self, text, tag = ""):
        self.print("{}\n".format(text), tag)
    def printMessage(self, name, message, tag = ""):
        self.printLine("{}: {}".format(name, message), tag)
    def printServerMessage(self, message):
        self.printMessage("[SERVER]", message, "server")
    def printError(self, message):
        self.printMessage("[ERROR]", message, "red")
    def printInfo(self, message):
        self.printMessage("[INFO]", message, "purple")

    def clear(self):
        self.print_mutex.acquire()
        self.message_area.config(state = "normal")
        self.message_area.delete("1.0", tk.END)
        self.message_area.config(state = "disabled")
        self.print_mutex.release()

    def printServerInfo(self):
        if self.socket == None:
            self.printError("No server")
        else:
            self.print_mutex.acquire()
            self.printInfo("========= SERVER INFO ==========")
            self.printInfo("HOST  {}".format(self.host))
            self.printInfo("PORT: {}".format(self.port))
            self.printInfo("================================")
            self.print_mutex.release()

    def disable(self):
        self.btn_send.config(state = "disabled")
        self.bind("<Return>", lambda event: True)

    def enable(self):
        self.btn_send.config(state = "normal")
        self.bind("<Return>", lambda event: self.sendMessageFromBox())

    def sendMessageFromBox(self):
        message = self.msg_entry.get()
        self.msg_entry.delete(0, "end")

        if message.rstrip() != "":
            self.printMessage(self.name, message, "own_message")

            if self.type == ChatWindow.SERVER:
                self.propagateMessage(None, message)

            elif self.type == ChatWindow.TYPE_CLIENT:
                self.socket_mutex.acquire()
                try:
                    self.sendStringMessage(message)
                except (ConnectionResetError, OSError):
                    self.goOffline()
                self.socket_mutex.release()

            else:
                raise AssertionError

    def sendIntTo(self, socket, integer, size = 4, signed = False):
        socket.sendall(integer.to_bytes(size, byteorder = "big", signed = signed))
    def sendByteTo(self, socket, byte, signed = False):
        socket.sendall(byte.to_bytes(1, byteorder = "big", signed = signed))
    def sendStringTo(self, socket, string):
        socket.sendall(string.encode())
    def sendMessageTo(self, socket, message):
        message = self.onSend(message)
        self.sendIntTo(socket, len(message))
        socket.sendall(message)
    def sendStringMessageTo(self, socket, message):
        self.sendMessageTo(socket, message.encode())

    def sendInt(self, integer, size = 4, signed = False):
        self.sendIntTo(self.socket, integer, size, signed)
    def sendByte(self, byte, signed = False):
        self.sendByteTo(self.socket, signed)
    def sendString(self, string):
        self.sendStringTo(self.socket, string)
    def sendMessage(self, message):
        self.sendMessageTo(self.socket, message)
    def sendStringMessage(self, message):
        self.sendStringMessageTo(self.socket, message)

    def receiveIntFrom(self, socket, size = 4, signed = False):
        return int.from_bytes(socket.recv(size), byteorder = "big", signed = signed)
    def receiveByteFrom(self, socket, signed = False):
        return int.from_bytes(socket.recv(1), byteorder = "big", signed = signed)
    def receiveStringFrom(self, socket, size):
        return socket.recv(size).decode()
    def receiveMessageFrom(self, socket):
        size = self.receiveIntFrom(socket)
        message = bytearray(size)
        received = socket.recv_into(message, size)
        if received != size:
            print("[ERROR]: Only", received, "bytes out of", size, "were received")
            message = b""
        else:
            message = self.onReceive(bytes(message))
        return message
    def receiveStringMessageFrom(self, socket):
        return self.receiveMessageFrom(socket).decode()

    def receiveInt(self, size = 4, signed = False):
        return self.receiveIntFrom(self.socket, size, signed)
    def receiveByte(self, signed = False):
        return self.receiveByteFrom(self.socket, signed)
    def receiveString(self, size):
        return self.receiveStringFrom(self.socket, size)
    def receiveMessage(self):
        return self.receiveMessageFrom(self.socket)
    def receiveStringMessage(self):
        return self.receiveStringMessageFrom(self.socket)

    def closeSocket(self):
        self.socket_mutex.acquire()
        self.socket.close()
        self.socket = None
        self.host = None
        self.port = None
        self.name = None
        self.socket_mutex.release()

    def goOffline(self):
        if self.type != None:
            self.disable()
            self.closeSocket()
            self.title("Chat")
            self.type = None

    def onClose(self):
        if messagebox.askokcancel("Quit", "Do you want to quit?"):
            self.goOffline()

            try:
                self.destroy()
            except tk.TclError:
                pass

    def onSend(self, data):
        return data

    def onReceive(self, data):
        return data


class LaunchWindowClient(tk.Toplevel):
    def __init__(self, parent, *args, **kwargs):
        tk.Toplevel.__init__(self, parent, *args, **kwargs)
        self.parent = parent
        self.title("Login")
        self.geometry("700x400")
        # self.wm_iconbitmap("assets/icon.ico")

        self.btn_connect = tk.Button(self, text = "Connect", command = self.checkvalues, width = 20, fg = "#FFCC33", bg = "#383a39")

        host_default = tk.StringVar(self, value = '192.168.56.1')
        self.host_entry = tk.Entry(self, width = 20, textvariable = host_default)

        port_default = tk.StringVar(self, value = '49155')
        self.port_entry = tk.Entry(self, width = 20, textvariable = port_default)

        nick_default = tk.StringVar(self, value = 'Nickname')
        self.nick_entry = tk.Entry(self, width = 20, textvariable = nick_default)

        self.configure(background = "#FFCC33")    #  yellow

        self.logo_image = None #tk.PhotoImage(file = "assets/Logo.gif")
        self.logo = tk.Label(self, image = self.logo_image, bg = "#FFCC33")
        self.logo.pack()

        self.blank = tk.Label(self, text = "<BLANK>", bg = "#FFCC33", fg = "#FFCC33")

        #  packing
        self.host_entry.pack()
        self.port_entry.pack()
        self.nick_entry.pack()

        self.blank.pack()
        self.btn_connect.pack()

        self.bind("<Return>", lambda event: self.checkvalues())

    def checkvalues(self):
        self.host = self.host_entry.get()

        try:
            socket.inet_aton(self.host)  # Throws a socket error if IP is illegal
        except socket.error:
            messagebox.showinfo("Error", "Not a valid IP address")
            return

        try:
            self.port = int(self.port_entry.get())
        except ValueError:
            messagebox.showinfo("Error", "Invalid port")
            return
        else:
            if self.port > 65535 or self.port < 0:
                messagebox.showinfo("Error", "Port must be 0-65535")
                return
            elif str(self.port) == "":
                messagebox.showinfo("Error", "Invalid port")
                return

        self.name = self.nick_entry.get()
        if self.name == "":
            messagebox.showinfo("Error", "Invalid name")
            return

        self.destroy()
        self.parent.connectToServer(self.host, self.port, self.name)


class LaunchWindowServer(tk.Toplevel):
    def __init__(self, parent, *args, **kwargs):
        tk.Toplevel.__init__(self, parent, *args, **kwargs)
        self.parent = parent
        self.title("~")
        x = self.parent.winfo_rootx() + 50
        y = self.parent.winfo_rooty() + 50
        geometry = "205x145+" + str(x) + "+" + str(y)
        self.geometry(geometry)

        self.host = socket.gethostbyname(socket.gethostname())
        if self.host == "127.0.0.1":
            self.host = socket.gethostbyname(socket.getfqdn())

        self.host_label = tk.Label(self, text = "Host IP:")
        self.port_label = tk.Label(self, text = "Host Port:")
        self.name_label = tk.Label(self, text = "Server Name:")

        self.host_label_filled = tk.Label(self, text = self.host)
        self.port_entry = tk.Entry(self, width = 20)
        self.name_entry = tk.Entry(self, width = 20)
        self.port_entry.insert(0, "49155")
        self.name_entry.insert(0, "Server")

        self.check_log_var = tk.IntVar()
        self.chatlog_checkbutton = tk.Checkbutton(self, text = "Enable Chatlog", variable = self.check_log_var)

        self.btn_start = tk.Button(self, text = "Start", command = self.checkvalues, width = 20)
        self.btn_scan = tk.Button(self, text = "Scan for available ports", command = self.portscan, width = 20)

        # Grid
        for i in range(1,2):
            self.grid_columnconfigure(i, weight = 1)
        for i in range(0,6):
            self.grid_rowconfigure(i, weight = 1)

        self.host_label.grid(row = 0, column = 0, sticky = "nswe")
        self.port_label.grid(row = 1, column = 0, sticky = "nswe")
        self.name_label.grid(row = 2, column = 0, sticky = "nswe")

        self.host_label_filled.grid(row = 0, column = 1, sticky = "nsw")
        self.port_entry.grid(row = 1, column = 1, sticky = "nswe", padx = 4)
        self.name_entry.grid(row = 2, column = 1, sticky = "nswe", padx = 4)

        self.chatlog_checkbutton.grid(row = 3, column = 0, columnspan = 2)

        self.btn_start.grid(row = 4, column = 0, columnspan = 2, sticky = "nswe", padx = 4, pady = 2)
        self.btn_scan.grid(row = 5, column = 0, columnspan = 2, sticky = "nswe", padx = 4, pady = 2)

        self.chatlog_checkbutton.select()  # Defaults to being checked
        self.bind("<Return>", lambda event: self.checkvalues())

        self.transient(self.parent)
        self.protocol("WM_DELETE_WINDOW", lambda event=None: self.destroy())
        self.grab_set()
        self.focus_set()
        self.parent.wait_window(self)

    def checkvalues(self):
        try:
            port = int(self.port_entry.get())
        except ValueError:
            messagebox.showinfo("Error", "Invalid port")
            return
        else:
            if port > 65535 or port < 0:
                messagebox.showinfo("Error", "Port must be 0-65535")
                return
            elif str(port) == "":
                messagebox.showinfo("Error", "Invalid port")
                return
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                try:
                    sock.bind((self.host, port))
                except OSError:
                    sock.close()
                    messagebox.showinfo("Error", "Port in use")
                    return
                else:
                    sock.close()

        name = self.name_entry.get()
        if name.rstrip() == "":
            messagebox.showinfo("Error", "Invalid server name")
            return

        log = self.check_log_var.get()
        self.destroy()
        self.parent.createServer(self.host, port, name, log)

    def portscan(self):
        # Disable buttons
        self.btn_start.config(state = "disabled")
        self.btn_scan.config(state = "disabled")
        self.bind("<Return>", lambda x: messagebox.showinfo("Please wait", "Still scanning ports"))

        # Only scans through iana approved free ports
        # https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml?&page=131
        for test_port in range(49152, 65536):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                sock.bind((self.host, test_port))
            except OSError:
                pass
            else:
                new_port = test_port
                sock.close()
                break
            sock.close()

        self.port_entry.delete(0, tk.END)
        self.port_entry.insert(0, new_port)

        # Re-enable buttons
        self.btn_start.config(state = "normal")
        self.btn_scan.config(state = "normal")
        self.bind("<Return>", lambda event: self.checkvalues())


if __name__ == "__main__":
    root = ChatWindow()
    root.mainloop()
