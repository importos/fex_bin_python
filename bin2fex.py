import struct
import string 
def fex(obj):
    return obj.__fex__()
class tag(object):
    def __init__(self,hf):
        self.pos=hf.tell()
        data=hf.read(40)
        if not data:
            raise Exception("no data")
        if len(data)<>40:
            raise Exception("invalid data")
        self.tag_name=data[:32]
        self.load_value(data[32:40])
        self.load_sub(hf)
    def load_value(self,data):
        raise Exception("Error")
    def load_sub(self,hf):
        raise Exception("Error")
    def _value_(self):
        return "No Value"
    def __str__(self):
        o1=hex(self.pos)+":"
        o1+=self.tag_name.replace("\x00"," ")
        o1+=self._value_()
        return o1
class master_tag(tag):
    def load_value(self,data):
        self.length=struct.unpack("I",data[:4])[0]
        self.sub_pos=struct.unpack("I",data[4:8])[0]*4
        
    def _value_(self):
        o1="number subs:"+str(self.length)
        o1+="   subs position:"+hex(self.sub_pos)
        for itm in self.subs:
            o1+="\x0d\x0a\x09"
            o1+=str(itm)
        return o1
    def load_sub(self,hf):
        self.subs=[]
        p1=hf.tell()
        hf.seek(self.sub_pos)
        cnt=0
        while(cnt<self.length):
            self.subs.append(sub_tag(hf))
            cnt+=1
        hf.seek(p1)
    def __fex__(self):
        o1="["
        o1+=self.tag_name.replace("\x00","")
        o1+="]"
        for itm in self.subs:
            o1+="\r\n\t"
            o1+=fex(itm)
        return o1
class sub_tag(tag):
    def load_value(self,data):
        self.sub_pos=struct.unpack("I",data[:4])[0]*4
        self.sub_length=struct.unpack("H",data[4:6])[0]*4
        self.sub_type=struct.unpack("H",data[6:8])[0]
    def port_string(self,value):
            v1=struct.unpack("iiiiii",value)
            v2=["A","00","default","default","default","default"]
            v2[0]=string.uppercase[v1[0]-1]
            v2[1]="%02d"%v1[1]
            for index in range(2,6):
                if v1[index]>=0:
                    v2[index]=str(v1[index])
            return ("port:P%s%s<%s><%s><%s><%s>  "%tuple(v2))
        
    def _value_(self):
        o1="sub position:"+hex( self.sub_pos)
        o1+="  sub type:"+hex( self.sub_type)
        o1+="  sub length:"+hex( self.sub_length)
        o1+="\x0d\x0a\x09\x09"
        if self.sub_type==1:
            v1=struct.unpack("I",self.subs)[0]
            o1+=hex(v1)+"\x09"+str(v1)
        elif self.sub_type==2:
            o1+="\""
            o1+=self.subs.replace("\x00","")
            o1+="\""
        elif self.sub_type==3:
            o1+=self.subs.encode("hex")
        elif self.sub_type==4:
            o1+=self.port_string(self.subs)
            o1+="   0x"
            o1+=self.subs.encode("hex")
        elif self.sub_type==5:
            o1+="NULL"
        else:
            o1+=self.subs.encode("hex")
            
        return o1
    def load_sub(self,hf):
        p1=hf.tell()
        hf.seek(self.sub_pos)
        self.subs=hf.read(self.sub_length)
        hf.seek(p1)
    def __fex__(self):
        o1=self.tag_name.replace("\x00","")
        o1+="="
        if self.sub_type==1:
            v1=struct.unpack("I",self.subs)[0]
            o1+="0x%08X"%v1
        elif self.sub_type==2:
            o1+="\""
            o1+=self.subs.replace("\x00","")
            o1+="\""
            
        elif self.sub_type==3:
            o1+=self.subs.encode("hex")
        elif self.sub_type==4:
            o1+=self.port_string(self.subs)
        elif self.sub_type==5:
            o1+=""
        else:
            o1+=self.subs.encode("hex")
        return o1
        
hf=open("script1.bin","rb")
hfout=open("script.txt","wb")
hffex=open("script.fex","wb")
p1=hf.read(16)
print p1.encode("hex")
file_size=struct.unpack("I",p1[4:8])[0]
tag_number=struct.unpack("I",p1[0:4])[0]
print "Tag Number:",hex(tag_number)
print "File Size:",hex(file_size)
tag_list=[]
while (len(tag_list) <tag_number):
    t1=master_tag(hf)
    tag_list.append(t1)
    print t1
    hfout.write(str(t1))
    hfout.write("\r\n")
    hffex.write(fex(t1))
    hffex.write("\r\n")
hf.close()
hfout.close()
hffex.close()
