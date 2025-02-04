import kbyg_bot

bind = "127.0.0.1:6666"
workers = 5


def on_exit(server):
    kbyg_bot.cleanup()
