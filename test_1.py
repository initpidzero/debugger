import subprocess
import time 
import sys 

'''
These are some of the common strings required for commands
for debugger
'''
quit = 'quit\n'
detach = 'detach\n'
attach = 'attach '
r = 'read '
w = 'write '
bp = 'break'
sig = 'signal'
regs = 'regs'     
step = 'step\n' 
cont = 'continue\n'
d = 'delete\n'

'''
This function compares results from text file dbg_log.txt
with Parameter: expected. If the result begin with expected string
it is a pass 
'''
def result_begin(expected):
    fd2 = open('./dbg_log.txt', 'r') #debugger sends all its output to this file
    res = 'FAIL'
    lines = fd2.readlines()
    for line in lines:
        if line.startswith(expected): #compare all lines.
            res = 'PASS'
    print res 
    fd2.close()

'''
This function compares results from text file dbg_log.txt
with Parameter: expected. If the result is exact match with expected string
it is a pass 
'''
def result(expected):
    fd2 = open('./dbg_log.txt', 'r')
    res = 'FAIL'
    lines = fd2.readlines()
    for line in lines:
        if line == expected:
            res = 'PASS'
    print res 
    fd2.close()

'''
This function compares results from text file dbg_log.txt
with toy.txt
with Parameter: expected1. If the result is exact match with expected1 string
with Parameter: expected2. If the result is exact match with expected2 string
it is a pass 
'''
def result_both(expected1, expected2):
    flag = 0
    res = 'FAIL'
    fd1 = open('./toy.txt', 'r')
    lines = fd1.readlines()
    for line in lines:
        if line == expected1:
            flag = flag + 1
            break
    fd2 = open('./dbg_log.txt', 'r')
    lines = fd2.readlines()
    for line in lines:
        if line == expected2:
            flag = flag + 1
            break
    if flag == 2:
            res = 'PASS'
    print res 
    fd1.close()
    fd2.close()

'''
This function compares results from text file dbg_log.txt for two strings
with Parameter: expected1. If the result is exact match with expected1 string
with Parameter: expected2. If the result is exact match with expected2 string
it is a pass 
'''
def result_double(expected1, expected2):
    fd2 = open('./dbg_log.txt', 'r')
    flag = 0
    res = 'FAIL'
    lines = fd2.readlines()
    for line in lines:
        if line == expected1:
            flag = flag + 1
            continue
        if line == expected2:
            flag = flag + 1
    if flag == 2:
        res = 'PASS'
    print res 
    fd2.close()

'''
This function exectues debuggee binary and returns subprocess object
Parameters: toy: binary name
Parameters: fd: file descriptor for dumping toy binary's stdout  
'''
def ex_toy(toy, fd):
    if fd != 0:
        t = subprocess.Popen(toy, stdout=fd)
    else:
        t = subprocess.Popen(toy)
    return t 

'''
This function exectues debuger binary and returns subprocess object
Parameters: argvs: list of string to be sent to debugger
Parameters: fd: file descriptor for dumping debugger's binary's stdout  
'''
def ex_dbg(argvs, fd):
    d = subprocess.Popen(argvs, stdout=fd)
    return d

'''
This function called debuger binary for testing  
Parameters: argvs: list of string to be sent to debugger
'''
def test(argvs):
    dbg_fd = open('./dbg_log.txt', 'w')

    ex_dbg(argvs, dbg_fd)
    dbg_fd.close()

    time.sleep(1) #wait for debuggee to finish writeing to dump file

'''
This function returns attach string with pid of debuggee  
Parameters: toy: debuggee binary name
'''
def att_str(toy):
    toy_fd = open('./toy.txt', 'w')
    t = ex_toy(toy, toy_fd)
    att = attach + str(t.pid) + '\n'
    toy_fd.close()
    return att

def tests():

    #test1
    i = 0
    dbg_fd = open('./dbg_log.txt', 'w') #open logging file for debugger output
    argvs = ['./dbg' , 'help\n', quit] #arguments are list of string

    print 'Test ' + str(i + 1) #print test number
    print 'Test if help command works' #print test description
    ex_dbg(argvs, dbg_fd) #execute debugger with arguments
    dbg_fd.close() #close debugger logging file

    expected = 'Commands supported\n' #expected string in debugger output
    time.sleep(1) #wait for a bit
    result(expected) #check in debugger log file if expected string is present

    #test2
    i = i + 1
    print 'Test ' + str(i + 1)
    print 'Test if attach/detach works' 
    att = att_str('./toy');# get string for attach argument with pid
    argvs = ['./dbg', att, detach ,quit]
    expected = 'Process attached\n'
    test(argvs) #execute debugger binary with logging
    result(expected)

    #test3
    i = i + 1
    print 'Test ' + str(i + 1)
    print 'Test if continue works' 
    att = att_str('./toy'); 
    argvs = ['./dbg', att, cont, quit]
    expected = 'Debuggee exits with status 0\n'
    test(argvs)
    result(expected)

    #test4
    i = i + 1
    print 'Test ' + str(i + 1)
    print 'Test if regs rip works' 
    att = att_str('./toy'); 
    reg = regs + ' ' + 'rip\n' #create string for getting rip value
    argvs = ['./dbg', att, reg, detach, quit]
    expected = 'rip' 
    test(argvs)
    result_begin(expected) #check if we get a string beginning with expected

    #test5
    i = i + 1
    print 'Test ' + str(i + 1)
    print 'Test if read works' 
    att = att_str('./toy'); 
    rd = r + ' ' + '0x6a30e8\n' #create read string with address
    argvs = ['./dbg', att, rd, detach, quit]
    expected = '6f77206f6c6c6568\n' 
    test(argvs)
    result(expected)

    #test6
    i = i + 1
    print 'Test ' + str(i + 1)
    print 'Test if write works' 
    att = att_str('./toy'); 
    #create write string with address and data
    wr = w + ' ' + '0x6a30e8 ' + '6767676767676767\n'
    rd = r + ' ' + '0x6a30e8\n'
    argvs = ['./dbg', att, wr, rd, detach, quit]
    expected = '6767676767676767\n'
    test(argvs)
    result(expected)

    #test7
    i = i + 1
    print 'Test ' + str(i + 1)
    print 'Test if breakpoint works' 
    att = att_str('./toy'); 
    br = bp + ' 400fa3\n' #create a breakpoint string
    argvs = ['./dbg', att, br, cont, d, cont, quit]
    expected = 'Breakpoint hit at 400fa3\n'
    test(argvs)
    result(expected)

    #test8
    i = i + 1
    print 'Test ' + str(i + 1)
    print 'Test if step works' 
    att = att_str('./toy'); 
    argvs = ['./dbg', att, step, detach, quit]
    expected = 'stepped\n' 
    test(argvs)
    result(expected)

    #test9
    i = i + 1
    print 'Test ' + str(i + 1)
    print 'Test if signal works' 
    att = att_str('./toy'); 
    s1 = sig + ' pass\n' #signal action set
    s2 = sig + '\n' #signal action get
    argvs = ['./dbg', att, s1, s2, detach, quit]
    expected = 'Current signal action: pass\n' 
    test(argvs)
    result(expected)

    #test10
    i = i + 1
    print 'Test ' + str(i + 1)
    print 'Test for delete breakpoint and reset breakpoint' 
    att = att_str('./toy'); 
    br1 = bp + ' 400f7c\n'
    br2 = bp + ' 400f80\n'#set breakpoint at next ip
    argvs = ['./dbg', att, br1, cont, d, br2, step, d, cont, quit]
    expected1 = 'Breakpoint hit at 400f7c\n'
    expected2 = 'Breakpoint hit at 400f80\n' #string for second breakpoint hit
    test(argvs)
    #check if both breakpoints are hit
    result_double(expected1, expected2)

    #test11
    i = i + 1
    print 'Test ' + str(i + 1)
    print 'Test if breakpoint works on last instruction' 
    att = att_str('./toy'); 
    br = bp + ' 400fc6\n'
    argvs = ['./dbg', att, br, cont, cont, quit]
    expected1 = 'Breakpoint hit at 400fc6\n'
    expected2 = 'Debuggee exits with status 0\n' #debuggee should exit
    test(argvs)
    result_double(expected1, expected2)

    #test12
    i = i + 1
    print 'Test ' + str(i + 1)
    print 'Test if breakpoint works on for()' 
    att = att_str('./toy'); 
    br = bp + ' 400f7c\n'
    argvs = ['./dbg', att, br, cont, d, detach, quit]
    expected = 'Breakpoint hit at 400f7c\n'
    test(argvs)
    result(expected)

    #test13
    i = i + 1
    print 'Test ' + str(i + 1)
    print 'Test for sigsegv'
    att = att_str('./sigsegv'); #call sigsegv binary
    s = sig + ' pass\n'
    argvs = ['./dbg', att, sig , cont, cont, quit]
    expected1 = 'SIGSEGV recieved\n'
    expected2 = 'Debuggee has received SIGSEGV\n'
    test(argvs)
    #expected1 appears in debugger log, expected2 appears in debuggee log
    result_both(expected1, expected2)

    #test14
    i = i + 1
    print 'Test ' + str(i + 1)
    print 'Test for sigill'
    att = att_str('./sigill');
    s = sig + ' pass\n'
    argvs = ['./dbg', att, sig , cont, cont, quit]
    expected1 = 'SIGILL recieved\n'
    expected2 = 'Debuggee has received SIGILL\n'
    test(argvs)
    result_both(expected1, expected2)

    #test15
    i = i + 1
    print 'Test ' + str(i + 1)
    print 'Test for sigfpe'
    att = att_str('./sigfpe');
    s = sig + ' pass\n'
    argvs = ['./dbg', att, sig , cont, cont, quit]
    expected1 = 'SIGFPE recieved\n'
    expected2 = 'Debuggee has received SIGFPE\n'
    test(argvs)
    result_both(expected1, expected2)

    #test16
    i = i + 1
    print 'Test ' + str(i + 1)
    print 'Test for continue after single step  and  set breakpoint' 
    att = att_str('./toy'); 
    br1 = bp + ' 400f7c\n' #first breakpoint
    br2 = bp + ' 400f80\n' #breakpoint on next value of RIP
    br3 = bp + ' 400f84\n' #breakpoint on next value of RIP
    argvs = ['./dbg', att, br1, cont, d, br2, step, d, br3, cont, d, detach, quit]
    expected1 = 'Breakpoint hit at 400f7c\n'
    expected2 = 'Breakpoint hit at 400f84\n'
    test(argvs)
    #we are only testing if first and third breakpoint are hit.
    result_double(expected1, expected2)

#if user wants to run a specific test?
if len(sys.argv) == 2:
    test_num = int(sys.argv[1])

'''
function to run various debugger tests
'''
tests()
