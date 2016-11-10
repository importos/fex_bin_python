import struct
import re
hffex=open("script.fex","rb")
hfbin=open("script.bin","wb")
fexlist=[]
cfex=""
clist=[]
while(True):
    data=hffex.readline()
    if not data:
        break
    d1=data.strip(" \t\r\n")
##    if d1[0]=="#":
##        continue
    if d1[0]=="[":
        fexlist.append((cfex,clist))
        clist=[]
        cfex=d1
    else:
        index=d1.find("=")
        if index == -1:
            raise Exception("not valid")
        clist.append((d1[:index],d1[index+1:]))
fexlist.pop(0)       
fexlist.append((cfex,clist))
l1=len(fexlist)
print hex(l1)
data=struct.pack("I",l1)
data+=struct.pack("I",0)
data+=struct.pack("I",1)
data+=struct.pack("I",2)
cdatapointer=len(data)/4
cdatapointer+=l1*10
for itm in fexlist:
    d1=itm[0][1:-1]
    l1=len(d1)
    l2=len(itm[1])
    if l1==0:
        continue
    if l1>32:
        continue
    data+=d1
    data+="\x00"*(32-l1)
    data+=struct.pack("I",l2)
    data+=struct.pack("I",cdatapointer)
    cdatapointer+=10*l2
valdata=""
p1=re.compile("^\".*\"$")
p2=re.compile("^0x.*$")
p3=re.compile("\b*port:P(?P<name>[ABCDEFGHIJKLMNOPQRSTUVWXYZ])(?P<number>[0123456789]{1,2})<(?P<set1>.*)><(?P<set2>.*)><(?P<set3>.*)><(?P<set4>.*)>$")
for itm in fexlist:
    for val in itm[1]:
        d1=val[1]
        if len(d1)==0:
            t1=5
            l1=1
            valdata+=struct.pack("I",0)
        elif p1.match(d1):
            t1=2
            l1=(len(d1[1:-1])/4)+1
            valdata+=d1[1:-1]
            valdata+="\x00"*(l1*4-len(d1[1:-1]))
        elif d1.isdigit():
            t1=1
            valdata+=struct.pack("I",int(d1))
            l1=1
        elif d1[:2]=="0x":
            t1=1
            valdata+=struct.pack("I",int(d1,16))
            l1=1
        elif p3.match(d1):
            d1= p3.match(d1).groupdict()
            v1=[ord(d1["name"])-64,int(d1["number"]),0,0,0,0]
            if d1["set1"].isdigit():
                v1[2]=int(d1["set1"])
            else:
                v1[2]=0xFFFFFFFF
            if d1["set2"].isdigit():
                v1[3]=int(d1["set2"])
            else:
                v1[3]=0xFFFFFFFF
            if d1["set3"].isdigit():
                v1[4]=int(d1["set3"])
            else:
                v1[4]=0xFFFFFFFF
            if d1["set4"].isdigit():
                v1[5]=int(d1["set4"])
            else:
                v1[5]=0xFFFFFFFF
            
            t1=4
            valdata+=struct.pack("IIIIII",*v1)

            l1=6
        
        else:
            t1=0
            l1=0
            raise Exception("Error "+d1+"   "+d1.encode("hex"))
        data+=val[0]
        data+="\x00"*(32-len(val[0]))
        data+=struct.pack("I",cdatapointer)
        data+=struct.pack("H",l1)
        data+=struct.pack("H",t1)
        cdatapointer+=l1
data+=valdata
lendata=struct.pack("I",len(data))
hfbin.write(data[:4])
hfbin.write(lendata)
hfbin.write(data[8:])

hfbin.close()
hffex.close()
