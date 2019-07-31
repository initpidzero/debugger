import subprocess
import time
import sys
import os

SRC=os.getcwd()
# Example binary name.
toy = '../toy'
# Debugger binary name.
dbg = '../dbg'

'''
These are some of the common strings required for commands
for debugger
Note some strings have trailing space, if the command requires a
parameter.
'''
QUIT = 'quit\n'
DET = 'detach\n'
ATT = 'attach '
RD = 'read '
WR = 'write '
BP = 'break'
SIG = 'signal'
REGS = 'regs'
STEP = 'step\n'
CONT = 'continue\n'
DEL = 'delete\n'

def result_begin(expected):
    '''
    Compares results from text file dbg_log.txt for beginning string to match.

    If the result begin with 'expected' string
    it is a pass

    expected:
        Comparison string.
    '''
    fd2 = open('./dbg_log.txt', 'r') #debugger sends all its output to this file
    res = 'FAIL'
    lines = fd2.readlines()
    for line in lines:
        if line.startswith(expected): #compare all lines.
            res = 'PASS'
    print res
    fd2.close()

def result(expected):
    '''
    Compares results from text file dbg_log.txt to be exact match.

    If the result is exact match with 'expected' string
    it is a pass

    expected:
        Comparison string.
        '''
    res = 'FAIL'
    fd2 = open('./dbg_log.txt', 'r')
    lines = fd2.readlines()
    for line in lines:
        if line == expected:
            res = 'PASS'
    print res
    fd2.close()

def result_none(expected):
    '''
    Compares results from text file dbg_log.txt to not match.

    If none of the string in dbg_log.txt matches with 'expected' string
    it is a pass

    expected:
        Comparison string.
        '''
    res = 'PASS'
    fd2 = open('./dbg_log.txt', 'r')
    lines = fd2.readlines()
    for line in lines:
        if line == expected:
            res = 'FAIL'
            break
    print res
    fd2.close()

def result_once(expected):
    '''
    Compare results only once from text file dbg_log.txt.

    If the results appear only once and are  exact match with 'expected'
    it is a pass.

    expected1:
        String for dbg_log.txt
    expected2:
        String for toy.txt
    '''
    flag = 0
    res = 'FAIL'
    fd = open('./dbg_log.txt', 'r')
    lines = fd.readlines()
    for line in lines:
        if line == expected:
            flag += 1
            break
    #pass if and only if string appears once in output 
    if flag == 1:
            res = 'PASS'
    print res
    fd.close()

def result_both(expected1, expected2):
    '''
    Compare results from text file dbg_log.txt and toy.txt.

    If the results are exact match with 'expected1' and 'expected2'
    it is a pass.

    expected1:
        String for dbg_log.txt
    expected2:
        String for toy.txt
    '''
    flag = 0
    res = 'FAIL'
    fd1 = open('./toy.txt', 'r')
    lines = fd1.readlines()
    for line in lines:
        if line == expected1:
            flag = flag + 1
            break #matching once is sufficient
    fd2 = open('./dbg_log.txt', 'r')
    lines = fd2.readlines()
    for line in lines:
        if line == expected2:
            flag = flag + 1
            break
    #pass if and only if both string in respective files match
    if flag == 2:
            res = 'PASS'
    print res
    fd1.close()
    fd2.close()

def result_double(expected1, expected2):
    '''
    Compare results from text file dbg_log.txt for two diffrent strings.
    If both strings are exact match  it is a pass.
    expected1:
        String 1 for exact match.
    expected2:
        String 2 for exact match.
    '''
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

def exe_dbg(argvs):
    '''
    Call debuger binary for testing

    argvs:
        list of string to be sent to debugger.
    '''
    dbg_fd = open('./dbg_log.txt', 'w')

    d = subprocess.Popen(argvs, stdout=dbg_fd)
    d.wait()
    dbg_fd.close()

    #time.sleep(2) #wait for debuggee to finish writeing to dump file

def att_str(toy):
    '''
    Create attach string with pid of debuggee.
    toy:
        debuggee binary name.
    return value:
        attach string with pid.
    '''
    toy_fd = open('./toy.txt', 'w')
    t = subprocess.Popen(toy, stdout=toy_fd)
    att = ATT + str(t.pid) + '\n'
    toy_fd.close()
    return att


def test1(i):
    print 'Test {0}'.format(i)  #print test number
    print 'Test if help command works' #print test description
    argvs = [dbg , 'help\n', QUIT] #arguments are list of string
    exe_dbg(argvs) #execute debugger binary with logging
    expected = 'Commands supported.\n' #expected string in debugger output
    result(expected) #check in debugger log file if expected string is present

def test2(i):
    print 'Test {0}'.format(i)  #print test number
    print 'Test if attach/detach works'
    att = att_str(toy);# get string for attach argument with pid
    argvs = [dbg, att, DET ,QUIT]
    exe_dbg(argvs) #execute debugger binary with logging
    expected = 'Process attached\n'
    result(expected)

def test3(i):
    print 'Test {0}'.format(i)
    print 'Test if continue works'
    att = att_str(toy);
    argvs = [dbg, att, CONT, QUIT]
    exe_dbg(argvs)
    expected = 'Debuggee exits with status 0\n'
    result(expected)

def test4(i):
    print 'Test {0}'.format(i)
    print 'Test if regs rip works'
    att = att_str(toy);
    reg = '{0} rip\n'.format(REGS) #create string for getting rip value
    argvs = [dbg, att, reg, DET, QUIT]
    exe_dbg(argvs)
    expected = 'rip'
    result_begin(expected) #check if we get a string beginning with expected

def test5(i):
    print 'Test {0}'.format(i)
    print 'Test if read works'
    att = att_str(toy);
    rd = '{0} 0x6a30e8\n'.format(RD) #create read string with address
    argvs = [dbg, att, rd, DET, QUIT]
    exe_dbg(argvs)
    expected = '6f77206f6c6c6568\n'
    result(expected)

def test6(i):
    print 'Test {0}'.format(i)
    print 'Test if write works'
    att = att_str(toy);
    #create write string with address and data
    wr = '{0} 0x6a30e8 6767676767676767\n'.format(WR)
    rd = '{0} 0x6a30e8\n'.format(RD) #create read string with address
    argvs = [dbg, att, wr, rd, DET, QUIT]
    exe_dbg(argvs)
    expected = '6767676767676767\n'
    result(expected)

def test7(i):
    print 'Test {0}'.format(i)
    print 'Test if breakpoint works'
    att = att_str(toy);
    br = '{0} 400fa3\n'.format(BP) #create a breakpoint string
    argvs = [dbg, att, br, CONT, DEL, CONT, QUIT]
    expected = 'Breakpoint hit at 400fa3\n'
    exe_dbg(argvs)
    result(expected)

def test8(i):
    print 'Test {0}'.format(i)
    print 'Test if step works'
    att = att_str(toy);
    argvs = [dbg, att, STEP, DET, QUIT]
    expected = 'Stepped\n'
    exe_dbg(argvs)
    result(expected)

def test9(i):
    print 'Test {0}'.format(i)
    print 'Test if signal works'
    att = att_str(toy);
    s1 = '{0} pass\n'.format(SIG) #signal action set
    s2 = '{0}\n'.format(SIG) #signal action get
    argvs = [dbg, att, s1, s2, DET, QUIT]
    expected = 'Current signal action: pass\n'
    exe_dbg(argvs)
    result(expected)

def test10(i):
    print 'Test {0}'.format(i)
    print 'Test for delete breakpoint and reset breakpoint'
    att = att_str(toy);
    br1 = '{0} 400f7c\n'.format(BP)
    br2 = '{0} 400f80\n'.format(BP) # set breakpoint at next ip
    argvs = [dbg, att, br1, CONT, DEL, br2, STEP, DEL, CONT, QUIT]
    expected1 = 'Breakpoint hit at 400f7c\n'
    expected2 = 'Breakpoint hit at 400f80\n' #string for second breakpoint hit
    exe_dbg(argvs)
    #check if both breakpoints are hit
    result_double(expected1, expected2)

def test11(i):
    print 'Test {0}'.format(i)
    print 'Test if breakpoint works on last instruction'
    att = att_str(toy);
    br = '{0} 400fc6\n'.format(BP)
    argvs = [dbg, att, br, CONT, CONT, QUIT]
    expected1 = 'Breakpoint hit at 400fc6\n'
    expected2 = 'Debuggee exits with status 0\n' #debuggee should exit
    exe_dbg(argvs)
    result_double(expected1, expected2)

def test12(i):
    print 'Test {0}'.format(i)
    print 'Test if breakpoint works on for()'
    att = att_str(toy);
    br = '{0} 400f7c\n'.format(BP)
    argvs = [dbg, att, br, CONT, DEL, DET, QUIT]
    expected = 'Breakpoint hit at 400f7c\n'
    exe_dbg(argvs)
    result(expected)

def test13(i):
    print 'Test {0}'.format(i)
    print 'Test for sigsegv'
    att = att_str('./sigsegv'); #call sigsegv binary
    s = '{0} pass\n'.format(SIG)
    argvs = [dbg, att, s, CONT, CONT, QUIT]
    expected1 = 'SIGSEGV recieved\n'
    expected2 = 'Debuggee has received SIGSEGV\n'
    exe_dbg(argvs)
    #expected1 appears in debugger log, expected2 appears in debuggee log
    result_both(expected1, expected2)

def test14(i):
    print 'Test {0}'.format(i)
    print 'Test for sigill'
    att = att_str('./sigill');
    s = '{0} pass\n'.format(SIG)
    argvs = [dbg, att, s, CONT, CONT, QUIT]
    expected1 = 'SIGILL recieved\n'
    expected2 = 'Debuggee has received SIGILL\n'
    exe_dbg(argvs)
    result_both(expected1, expected2)

def test15(i):
    print 'Test {0}'.format(i)
    print 'Test for sigfpe'
    att = att_str('./sigfpe');
    s = '{0} pass\n'.format(SIG)
    argvs = [dbg, att, s, CONT, CONT, QUIT]
    expected1 = 'SIGFPE recieved\n'
    expected2 = 'Debuggee has received SIGFPE\n'
    exe_dbg(argvs)
    result_both(expected1, expected2)

def test16(i):
    print 'Test {0}'.format(i)
    print 'Test for continue after single step and set breakpoint'
    att = att_str(toy);
    br1 = '{0} 400f7c\n'.format(BP) #first breakpoint
    br2 = '{0} 400f80\n'.format(BP) #breakpoint on next value of RIP
    br3 = '{0} 400f84\n'.format(BP) #breakpoint on next value of RIP
    argvs = [dbg, att, br1, CONT, DEL, br2, STEP, DEL, br3, CONT, DEL, DET, QUIT]
    expected1 = 'Breakpoint hit at 400f7c\n'
    expected2 = 'Breakpoint hit at 400f84\n'
    exe_dbg(argvs)
    #we are only testing if first and third breakpoint are hit.
    result_double(expected1, expected2)

def test17(i):
    print 'Test {0}'.format(i)
    print 'Test if no breakpoints are left in debuggee'
    att = att_str(toy);
    br = '{0} 400fa3\n'.format(BP) #create a breakpoint string
    argvs = [dbg, att, br, CONT, DEL, CONT, QUIT]
    expected1 = 'Breakpoint hit at 400fa3\n'
    expected2 = 'Debuggee exits with status 0\n'
    exe_dbg(argvs)
    result_double(expected1, expected2)

def tests(user_input):
    '''
    Perform various tests.

    i:
        Test number to run. 0 means run all tests.
    '''
    all_tests = [
                test1, test2, test3, test4, test5, test6, test7,
                test8, test9, test10, test11, test12, test13,
                test14, test15, test16, test17
                ]

    if user_input == 'all':
        for i, test_list in enumerate(all_tests):
            test_list(i + 1)
    if user_input.isdigit():
        i = int(user_input)
        if int(i) > 0 and int(i) < len(all_tests) + 1:
            all_tests[i - 1](i)

if __name__ == '__main__':
    # Run all tests if no input is provided by user.
    user_input = 'all'
    # User input either category or number of test to run
    if len(sys.argv) == 2:
        user_input = sys.argv[1]

    #run all test.
    tests(user_input)
