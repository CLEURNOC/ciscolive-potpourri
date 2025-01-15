import dhcp_bot

bind = "127.0.0.1:9999"
workers = 5


def on_exit(server):
    dhcp_bot.cleanup()
