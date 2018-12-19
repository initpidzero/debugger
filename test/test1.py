import subprocess

p = subprocess.Popen("./dbg", stdout=subprocess.PIPE, stdin=subprocess.PIPE)
pid = p.pid
print pid
stuff = p.stdout.read()
print stuff
p.stdin.write('help\n'.encode())
p.stdin.flush()
stuff = p.stdout.read()
print stuff
p.stdin.write('quit\n'.encode())
p.stdin.flush()
stuff = p.stdout.read()
print stuff
