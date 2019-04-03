#!/usr/bin/python3
from datetime import datetime   # For timestamping messages
from tkinter import messagebox  # Quit dialouge box
import tkinter as tk            # GUI
import socket                   # Socket connections
import threading                # Running multiple functions at once
import requests

class ChatWindow(tk.Tk):
    TYPE_NONE = None
    TYPE_CLIENT = 0
    TYPE_SERVER = 1

    class Message():
        TYPE_NORMAL      = 0
        TYPE_SERVER      = 1
        TYPE_KICK        = 2
        TYPE_NAME_IN_USE = 3
        TYPE_FILE        = 4

        def __init__(self, type = None, name = None, msg = None):
            self.type = type
            self.name = name
            self.text = msg

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
        self.client_dict = {}
        self.buffer_size = 128
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
                    self.socket.listen(5) # 5 = Connection queue
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
            self.type = ChatWindow.TYPE_SERVER
            self.enable()

        self.socket_mutex.release()
        self.print_mutex.release()

    def closeServer(self):
        if self.type == ChatWindow.TYPE_SERVER:
            self.socket_mutex.acquire()
            self.print_mutex.acquire()

            for client in self.client_dict.keys():
                client.close()
            self.client_dict.clear()

            self.goOffline()
            self.printInfo("Server Stopped")
            if self.chatlogfile != None:
                self.chatlogfile.close()
                self.chatlogfile = None

            self.socket_mutex.release()
            self.print_mutex.release()

    def propagateServerMessage(self, message):
        self.socket_mutex.acquire()

        for client in self.client_dict.keys():
            try:
                self.sendByteTo(client, ChatWindow.Message.TYPE_SERVER)
                self.sendIntTo(client, len(message))
                self.sendTextTo(client, message)
            except (BrokenPipeError, OSError):
                client.close()
                self.client_dict.pop(client)

        self.socket_mutex.release()

    def propagateMessage(self, sender, message):
        self.socket_mutex.acquire()

        for client, client_name in self.client_dict.items():
            if client_name != sender:
                try:
                    self.sendByteTo(client, ChatWindow.Message.TYPE_NORMAL)
                    self.sendIntTo(client, len(sender))
                    self.sendTextTo(client, sender)
                    self.sendIntTo(client, len(message))
                    self.sendTextTo(client, message)
                except (BrokenPipeError, OSError):
                    client.close()
                    self.client_dict.pop(client)

        self.socket_mutex.release()

    def kick(self, client_name):
        self.socket_mutex.acquire()
        self.print_mutex.acquire()

        name_map = {v: k for k, v in self.client_dict.items()}

        try:
            client_to_kick = name_map[client_name]
            self.sendByteTo(client_to_kick, ChatWindow.Message.TYPE_KICK)
            client_to_kick.close()

            kick_msg = "{} was kicked from server".format(client_name)
            self.printInfo(kick_msg)
            self.propagateServerMessage(kick_msg)

        except KeyError:
            self.printError("Invalid name {}".format(client_name))

        self.socket_mutex.release()
        self.print_mutex.release()

    def listen(self):
        while self.socket != None:
            try:
                client, addr = self.socket.accept()

            except OSError:
                self.socket_mutex.acquire()
                if self.socket != None:
                    self.printError("OSError raised while waiting for new client connections")
                    self.closeServer()
                self.socket_mutex.release()

            else:
                self.socket_mutex.acquire()
                self.print_mutex.acquire()

                ip_port = "{}:{}".format(addr[0], addr[1])
                self.printInfo("Accepted connection from: {}".format(ip_port))

                client_name = None

                try:
                    size = self.receiveIntFrom(client)
                    client_name = self.receiveTextFrom(client, size)

                    if client_name in self.client_dict.values():
                        self.sendByteTo(client, ChatWindow.Message.TYPE_NAME_IN_USE)
                        client.close()
                        self.printInfo("Client {} tried connecting with '{}' - already in use".format(ip_port, client_name))
                    else:
                        self.client_dict[client] = client_name

                        message = "Your connection was successful!\n"
                        self.sendByteTo(client, ChatWindow.Message.TYPE_SERVER)
                        self.sendIntTo(client, len(message))
                        self.sendTextTo(client, message)

                        self.printInfo("Client {} ({}) connection successful".format(client_name, ip_port))
                        self.propagateServerMessage("{} joined".format(client_name))

                except (ConnectionResetError, ConnectionAbortedError, OSError):
                    if client_name == None:
                        self.printInfo("Unknown client ({}) disconnected before full connection".format(ip_port))
                    else:
                        self.client_dict.pop(client)
                        self.propagateServerMessage(client, "Client {} disconnected".format(client_name))
                        self.printInfo("Client {} ({}) disconnected".format(client_name, ip_port))

                    client.close()

                else:
                    self.print_mutex.release()
                    self.socket_mutex.release()

                    client_handler_thread = threading.Thread(target = self.handleClient, args = (client, client_name, addr))
                    client_handler_thread.daemon = True
                    client_handler_thread.start()

    def handleClient(self, client, client_name, addr):
        while client != None:
            try:
                message = self.receiveTextFrom(client, self.buffer_size)
                self.printMessage(client_name, message)
                self.propagateMessage(client_name, message)

            except (ConnectionResetError, ConnectionAbortedError, OSError):
                self.socket_mutex.acquire()

                try:
                    self.client_dict.pop(client)
                    client.close()
                except KeyError:
                    pass
                else:
                    self.propagateServerMessage("Client {} disconnected".format(client_name))
                    self.printInfo("Client {} ({}:{}) disconnected".format(client_name, addr[0], addr[1]))

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
            self.printError("Socket attempted to connect to an unreachable network")
            self.printError("[Debug Info] IP:{}, Port:{}, Name:{}".format(self.host, self.port, self.name))
            self.closeSocket()
        except ConnectionRefusedError:
            self.printError("No connection could be made")
            self.printError("[Debug Info] IP:{}, Port:{}, Name:{}".format(self.host, self.port, self.name))
            self.closeSocket()
        else:
            self.printInfo("Connected to server")
            self.sendInt(len(self.name))
            self.sendText(self.name)
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
        msg = ChatWindow.Message()

        while self.socket != None:
            try:
                msg.type = self.receiveByte()

                if msg.type == ChatWindow.Message.TYPE_NORMAL:
                    size = self.receiveInt()
                    msg.name = self.receiveText(size)
                    size = self.receiveInt()
                    msg.text = self.receiveText(size)

                    self.printMessage(msg.name, msg.text)

                elif msg.type == ChatWindow.Message.TYPE_SERVER:
                    size = self.receiveInt()
                    msg.text = self.receiveText(size)

                    self.printServerMessage(msg.text)

                elif msg.type == ChatWindow.Message.TYPE_KICK:
                    self.printServerMessage("You have been kicked")
                    raise ConnectionResetError

                elif msg.type == ChatWindow.Message.TYPE_NAME_IN_USE:
                    self.printServerMessage("Name already in use")
                    raise ConnectionResetError

                elif msg.type == ChatWindow.Message.TYPE_FILE:
                    self.printError("msg.type == ChatWindow.Message.TYPE_FILE")

                else:
                    self.printError("Unknown message type from server: {}".format(msg.type))
                    self.socket.recv(1024)

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
        self.write("{} | {}".format(datetime.now().strftime("%H:%M"), text), tag)
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

            if self.type == ChatWindow.TYPE_SERVER:
                self.propagateMessage(self.name, message)

            elif self.type == ChatWindow.TYPE_CLIENT:
                self.socket_mutex.acquire()
                try:
                    self.sendText(message)
                except (ConnectionResetError, OSError):
                    self.closeSocket()
                self.socket_mutex.release()

            else:
                raise AssertionError

    def sendIntTo(self, socket, integer, size = 4, signed = False):
        socket.send(integer.to_bytes(size, byteorder = "big", signed = signed))
    def sendByteTo(self, socket, byte, signed = False):
        socket.send(byte.to_bytes(1, byteorder = "big", signed = signed))
    def sendTextTo(self, socket, text):
        socket.send(text.encode())

    def sendInt(self, integer, size = 4, signed = False):
        self.sendIntTo(self.socket, integer, size, signed)
    def sendByte(self, byte, signed = False):
        self.sendByteTo(self.socket, signed)
    def sendText(self, text):
        self.sendTextTo(self.socket, text)

    def receiveIntFrom(self, socket, size = 4, signed = False):
        return int.from_bytes(socket.recv(size), byteorder = "big", signed = signed)
    def receiveByteFrom(self, socket, signed = False):
        return int.from_bytes(socket.recv(1), byteorder = "big", signed = signed)
    def receiveTextFrom(self, socket, size):
        return socket.recv(size).decode()

    def receiveInt(self, size = 4, signed = False):
        return self.receiveIntFrom(self.socket, size, signed)
    def receiveByte(self, signed = False):
        return self.receiveByteFrom(self.socket, signed)
    def receiveText(self, size):
        return self.receiveTextFrom(self.socket, size)

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

        self.logo_image = None #tk.PhotoImage(file = "assets/logo.gif")
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
