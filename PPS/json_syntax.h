#ifndef PPS_PROJECT_JSON_SYNTAX_H_INCLUDED
#define PPS_PROJECT_JSON_SYNTAX_H_INCLUDED

#include <cstddef>
#include <cstdint>
#include <cstring>

class JsonSyntax {
  const uint8_t* p;size_t n,i=0;
  void space(){while(i<n&&(p[i]==' '||p[i]=='\t'||p[i]=='\r'||p[i]=='\n'))i++;}
  bool eat(char c){if(i<n&&p[i]==uint8_t(c)){i++;return true;}return false;}
  bool digit(){return i<n&&p[i]>='0'&&p[i]<='9';}
  bool literal(const char* s){size_t count=strlen(s);if(n-i<count||memcmp(p+i,s,count))return false;i+=count;return true;}
  bool hex4(uint16_t& out){
    out=0;if(n-i<4)return false;
    for(int k=0;k<4;k++){uint8_t c=p[i++];int v=c>='0'&&c<='9'?c-'0':c>='a'&&c<='f'?c-'a'+10:c>='A'&&c<='F'?c-'A'+10:-1;if(v<0)return false;out=uint16_t((out<<4)|v);}return true;
  }
  bool string(){
    if(!eat('"'))return false;
    while(i<n){
      uint8_t c=p[i++];if(c=='"')return true;if(c<32)return false;
      if(c=='\\'){
        if(i==n)return false;c=p[i++];
        if(c=='u'){
          uint16_t code;if(!hex4(code)||!code)return false;
          if(code>=0xd800&&code<=0xdbff){uint16_t low;if(!eat('\\')||!eat('u')||!hex4(low)||low<0xdc00||low>0xdfff)return false;}
          else if(code>=0xdc00&&code<=0xdfff)return false;
        }else if(c!='"'&&c!='\\'&&c!='/'&&c!='b'&&c!='f'&&c!='n'&&c!='r'&&c!='t')return false;
      }else if(c>=128){
        unsigned count;uint32_t cp,min;
        if(c>=0xc2&&c<=0xdf){count=1;cp=c&31;min=0x80;}
        else if(c>=0xe0&&c<=0xef){count=2;cp=c&15;min=0x800;}
        else if(c>=0xf0&&c<=0xf4){count=3;cp=c&7;min=0x10000;}else return false;
        if(n-i<count)return false;
        for(unsigned k=0;k<count;k++){uint8_t next=p[i++];if((next&0xc0)!=0x80)return false;cp=(cp<<6)|(next&63);}
        if(cp<min||cp>0x10ffff||(cp>=0xd800&&cp<=0xdfff))return false;
      }
    }
    return false;
  }
  bool number(){
    eat('-');if(!eat('0')){if(!digit())return false;while(digit())i++;}
    if(eat('.')){if(!digit())return false;while(digit())i++;}
    if(eat('e')||eat('E')){if(!eat('+'))eat('-');if(!digit())return false;while(digit())i++;}return true;
  }
  bool value(unsigned depth){
    space();if(i==n||depth>8)return false;
    if(p[i]=='"')return string();
    if(eat('{')){
      space();if(eat('}'))return true;
      do{space();if(!string())return false;space();if(!eat(':')||!value(depth+1))return false;space();if(eat('}'))return true;}while(eat(','));return false;
    }
    if(eat('[')){
      space();if(eat(']'))return true;
      do{if(!value(depth+1))return false;space();if(eat(']'))return true;}while(eat(','));return false;
    }
    if(p[i]=='t')return literal("true");if(p[i]=='f')return literal("false");if(p[i]=='n')return literal("null");return number();
  }
public:
  JsonSyntax(const uint8_t* data,size_t size):p(data),n(size){}
  bool valid(){if(!p||!value(0))return false;space();return i==n;}
};

#endif
