# -*- coding: utf-8 -*-

from idaapi import *
from idc import *
import sys

#设置深度递归数为1k
sys.setrecursionlimit(1000)

global g_MaxSteps
global g_MaxRecurseCount
global g_MaxBufSize
global g_MinBufSize
global g_Problem
global g_ProblemNum
global g_ProblemType

def GetArgBufSize(addr, index):
    global g_MaxSteps
    count = g_MaxSteps
    #获取第index条push指令参数的位置（不一定是push，也可能是mov [esp+4],aaa这种形式，因此不能简单地去搜索‘push’）
    eaPush = GetArgPush(addr, index)
    cOpnd = GetOpnd(eaPush, 0)
    #push全局变量的情况，直接去找全局变量的大小
    if "offset" in cOpnd:
        return BuffSize(eaPush, 0)
    #push [eax]这种情况，无法准确回溯到初始变量，此处不考虑
    if "[" in cOpnd:
        return 0
    #push eax这种情况，往前回溯相应寄存器值的来源
    eaCurr = RfirstB(eaPush)
    #寻找上一条具有相同操作数的指令
    while cOpnd != GetOpnd(eaCurr, 0) and count != 0:
        eaCurr = RfirstB(eaCurr)
        count = count - 1
    #print "GetArgBufSize ret %d"%BuffSize(eaCurr, 1)
    return BuffSize(eaCurr, 1)

#获取对应于该call指令的第n条push指令的地址

def GetArgPush(eaCall, index):
    global g_MaxSteps
    maxstep = g_MaxSteps
    eaCurr = eaCall
    #获取call指令位置处的栈偏移，作为基准栈偏移
    spdA = GetSpd(eaCall)

    while maxstep > 0:
        #循环回溯指令，检查该指令处栈偏移是否有变化
        eaCurr = RfirstB(eaCurr)
        spdB = GetSpd(eaCurr)
        #只有与参数入栈有关的指令才会与基准栈偏移成如下关系：第一个参数的话差值为4，第二个参数为差值8
        if spdB - (index * 4) == spdA:
            #返回该call指令的第index条push指令的地址
            return eaCurr
        maxstep -= 1
    return -1

def BuffSize(eaInstruc, iOpnum):
    global g_MaxSteps
    global g_MaxRecurseCount
    global g_MaxBufSize
    global g_MinBufSize
    Opnd = GetOpnd(eaInstruc, iOpnum)
    if ("ebp" in Opnd) or ("esp" in Opnd):
        #去掉寄存器名，取得变量偏移
        while "+" in Opnd:
            Opnd = Opnd[Opnd.find("+", 0, len(Opnd))+1:-1]
            #上面的-1已经截断断后方括号了
            #Opnd = Opnd[0:Opnd.find("]", 0, len(Opnd))]
            #Opnd = substr( Opnd,  strstr( Opnd,  "+")+1,  -1)
            #Opnd = substr( Opnd,  0,  strstr(Opnd,  "]") )
        #print Opnd
        #获取对应的函数框架结构ID
        strucID = GetFrame(eaInstruc)

        if GetMemberByName(strucID, Opnd) > GetMemberByName(strucID, " r"):
            g_MaxRecurseCount = g_MaxRecurseCount + 1
            if g_MaxRecurseCount < g_MaxSteps:
                #计算参数号
                argnum = (GetMemberByName(strucID, Opnd)-GetMemberByName(strucID, " r"))/4
                funcbegin = LocByName(GetFunctionName(eaInstruc))
                #可能的最大值
                minval = 0x7FFFFFFF
                maxval = 0
                #TEXT的情况
                xrefloc = RfirstB(funcbegin)
                while xrefloc != BADADDR:
                    if GetMnem(xrefloc) == "call":
                        bufsz = GetArgBufSize(xrefloc, argnum)
                        if bufsz > maxval:
                            maxval = bufsz
                        if bufsz < minval and bufsz > 0:
                            minval = bufsz
                    xrefloc = RnextB(funcbegin, xrefloc)
                #DATA的情况
                xrefloc = DfirstB(funcbegin)
                while xrefloc != BADADDR:
                    if GetMnem(xrefloc) == "call":
                        bufsz = GetArgBufSize(xrefloc, argnum)

                        if bufsz > maxval:
                            maxval = bufsz
                        if bufsz < minval and bufsz > 0:
                            minval = bufsz
                    xrefloc = DnextB(funcbegin, xrefloc)
                #可以确定变量大小了
                if minval == 0x7FFFFFFF or maxval == 0:
                    minval = -1
                    maxval = -1
                g_MaxBufSize = maxval
                g_MinBufSize = minval
                #print "BufSize 1 ret %d"%minval
                return minval
            else:
                g_MaxBufSize = -1
                g_MinBufSize = -1
                return -1
        else:
            if GetMnem(eaInstruc) == "mov":
                minval = -1
            else:
                minval = StckBuffSize(eaInstruc, Opnd)
            g_MinBufSize = minval
            g_MaxBufSize = minval
            #print "BufSize 2 ret=%d, eaInstruc=%d"%(minval, eaInstruc)
            return minval

    elif "offset" in Opnd:
        Opnd = Opnd[Opnd.find("offset", 0, len(Opnd))+7:-1]
        #Opnd = substr(Opnd,  strstr(Opnd,  "offset ")+7,  -1)
        minval = SHeapBuffSize(LocByName(Opnd))
        g_MinBufSize = minval
        g_MaxBufSize = minval
        return minval
    elif "." in Opnd:
        if "["  in Opnd:
            Opnd = Opnd[Opnd.find("[", 0, len(Opnd))+1:Opnd.find("]", 0, len(Opnd))]
            #Opnd = substr(Opnd,  strstr(Opnd,  "[")+1,  strstr(Opnd,  "]"))
        if "+"  in Opnd:
            Opnd = Opnd[Opnd.find("+", 0, len(Opnd))+1:-1]
            #Opnd = substr(Opnd,  strstr(Opnd,  "+")+1,  -1)
        strucID = GetStrucIdByName(Opnd[0:Opnd.find(".", 0, len(Opnd))])
        #strucID = GetStrucIdByName(substr(Opnd,  0,  strstr(Opnd,  ".")))
        minval = StrucBuffSize(strucID, Opnd[Opnd.find(".", 0, len(Opnd))+1:-1])
        #minval = StrucBuffSize(strucID, substr(Opnd,  strstr(Opnd,  ".")+1,  -1))
        g_MinBufSize = minval
        g_MaxBufSize = minval
        return minval

def GetMemberByName(strucId, cName):
    ofs = GetFirstMember(strucId)
    while GetMemberName(strucId, ofs) != cName and ofs != -1:
        ofs = GetStrucNextOff(strucId, ofs)
    return ofs

def BinStrGet(lpAddr):
    strTemp = ""
    chr = Byte(lpAddr)
    while chr != 0 and chr != 0xFF:
        strTemp = "%s%c"%(strTemp, chr)
        lpAddr = lpAddr + 1
        chr = Byte(lpAddr)
    #print "BinStrGet ret :%s"%strTemp
    return strTemp

def GetArgImmed(lpCall, numarg):
    argpush = GetArgPush(lpCall, numarg)
    Opnd = GetOpnd(argpush, 0)
    #要分别考虑16和10进制
    if Opnd[len(Opnd)-1:-1] == "h":
    #if substr( Opnd,  strlen(Opnd)-1,  -1 ) == "h" :
        val = xtol(Opnd)
    else:
        val = atol(Opnd)
    return val

def GetArgStr(lpCall, numarg):
    argpush = GetArgPush(lpCall, numarg)
    Opnd = GetOpnd(argpush, 0)
    if "offset" in Opnd:
        return ""
    loc = LocByName(Opnd[Opnd.find("offset", 0, len(Opnd))+len("offset"):-1])
    #loc = LocByName(substr( Opnd,  strstr(Opnd,  "offset") + strlen("offset "),  -1 ))
    return BinStrGet(loc)

def StckBuffSize(lpCall, cName):
    frameID = GetFrame(lpCall)
    count = StrucBuffSize(frameID, cName)
    return count

def StrucBuffSize(strucID, cName):
    ofs = GetMemberOffset(strucID, cName)
    if ofs == -1:
        return 0

    count = ofs + 1
    memName = GetMemberName(strucID, count)
    #print "StrucBuffSize memName1=%s"%(memName)
    while memName == cName or memName == None:
        count = count +1
        memName = GetMemberName(strucID, count)
        #print "StrucBuffSize memName2=%s"%(memName)
        if count > GetStrucSize(strucID):
            return -1
    count = count - ofs
    #print "StrucBuffSize ret=%d, strucID=%lx, cName=%s"%(count, strucID, cName)
    return count

def SHeapBuffSize(eaBuff):
    count = 1
    while Name(eaBuff + count) == None:
        count = count + 1
    return count

def GetFunctionTpye(funcname):
    if "sprintf" in funcname:
        #sprintf(), _sprintf()的情况
        return "SPRINTF"
    else:
        #strcpy(), _strcpy(), strcat(), _strcat()的情况
        return "STRC"

def AuditSTRC(addr, function):
    global g_MaxBufSize
    global g_Problem
    global g_ProblemNum
    global g_ProblemType

    #获得该处call源和目标缓冲区小可能的大小，-1/0表示未知大小
    DestMinSize = GetArgBufSize(addr, 1)
    DestMaxSize = g_MaxBufSize

    SrcMinSize = GetArgBufSize(addr, 2)
    SrcMaxSize = g_MaxBufSize
    #
    #print "SIZE:%d, %d, %d, %d"%(DestMinSize, DestMaxSize, SrcMinSize, SrcMaxSize)
    #如果任有有一个缓冲区的大小不能静态分析出来
    if (DestMinSize == -1 or DestMinSize == 0) and SrcMinSize != -1:
            print "[!]-> Error!UNKNOWN DESTINATION SIZE:0x%lx"%(addr)
    elif DestMinSize != -1 and (SrcMinSize == 0 or SrcMinSize == -1):
            print "[!]-> Error!UNKNOWN SOURCE SIZE:0x%lx"%(addr)
    elif (DestMinSize == -1 or DestMinSize == 0) and (SrcMinSize == -1 or SrcMinSize == 0):
            print "[!]-> Error!UNKNOWN_SOURCE_DEST_SIZE:0x%lx"%(addr)
    #能分析出缓冲区拷贝大小的情况，可确定存在溢出
    elif DestMaxSize < SrcMinSize:
        g_Problem.append(addr)
        g_ProblemType.append(function)
        g_ProblemNum = g_ProblemNum + 1
    elif DestMaxSize < SrcMaxSize:
        g_Problem.append(addr)
        g_ProblemType.append(function)
        g_ProblemNum = g_ProblemNum + 1
    elif DestMinSize < SrcMaxSize:
        g_Problem.append(addr)
        g_ProblemType.append(function)
        g_ProblemNum = g_ProblemNum + 1
    else:
        return

def AuditSPRINTF(addr, function):
    formatstr = GetArgStr(addr, 2)
    argcount = 2
    maxlen = len(formatstr)
    hasstr = 0
    while "%%" in formatstr:
        formatstr = formatstr[0:formatstr.find("%%", 0, len(formatstr))]+formatstr[formatstr.find("%%", 0, len(formatstr))+2:-1]
    while "%" in formatstr:
        argcount += 1
        index1 = formatstr.find("%")
        index2 = formatstr.find("%s")
        if index2 == -1:
            break
        if index1 == index2:
            argbufsize = GetArgBufSize(addr, argcount)
            if argbufsize != -1:
                maxlen = maxlen + argbufsize
                hasstr = 1
            else:
                return
        formatstr = formatstr[index1+1:-1]
    maxlen = maxlen - (argcount - 2) * 2
    targetsize = GetArgBufSize(addr, 1)
    if targetsize == 0 or targetsize == -1:
        print "[!]-> Error!UNKNOWN TARGET SIZE:0x%lx"%(addr)
    elif targetsize < maxlen and hasstr != 0:
        g_Problem.append(addr)
        g_ProblemType.append(function)
        g_ProblemNum = g_ProblemNum + 1
    else:
        return

def Audit(addr, function):
    print "[+]Find a %s() at 0x%lx"%(function, addr)
    functype=GetFunctionTpye(function)
    if functype == "STRC":
        AuditSTRC(addr, function)
    elif functype == "SPRINTF":
        AuditSPRINTF(addr, function)
    return

def main():

    global g_MaxSteps
    global g_MaxRecurseCount
    global g_MaxBufSize
    global g_MinBufSize
    global g_Problem
    global g_ProblemNum
    global g_ProblemType

    g_MaxSteps = 50
    g_MaxRecurseCount = 0
    g_MaxBufSize = 0
    g_MinBufSize = 0
    g_Problem = []
    g_ProblemNum = 0
    g_ProblemType = []
    #定义需要分析的函数
    #目前只支持下列函数
    Functions = [
    "strcpy", 
    "strcat", 
    "_strcpy", 
    "_strcat", 
    "sprintf", 
    "_sprintf", 
    "wsprintfA", 
    "lstrcpyA", 
    "lstrcatA"
    ]

    print "[*]==========> Auditing ...<==========="
    for Function in Functions:
        FuncAddr = LocByName(Function)
        if FuncAddr == BADADDR:
            break

        xref = RfirstB(FuncAddr)
        while xref != BADADDR:
            if GetMnem(xref) == "call":
                Audit(xref, Function)
            xref = RnextB(FuncAddr, xref)
    
        xref = DfirstB(FuncAddr)

        while xref != BADADDR:
            if GetMnem(xref) == "call":
                Audit(xref, Function)
            xref = DnextB(FuncAddr, xref)

    print "[*]=========>Audit completed<=========="

    if g_ProblemNum != 0:
        print "[+]Find %d overflow(s) :"%(g_ProblemNum)
        for Problem in g_Problem:
            print "[+]A %s() overflow at addr = 0x%lx"%(g_ProblemType[g_Problem.index(Problem)], Problem)
    else:
        print "[*]No overflows. _(:з」∠)_"

#入口
def SearchOverflow():
    main()
