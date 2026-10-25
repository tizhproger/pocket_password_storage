#ifndef PPS_PROJECT_DISPLAY_TEXT_H_INCLUDED
#define PPS_PROJECT_DISPLAY_TEXT_H_INCLUDED

#include "secure.h"
namespace DisplayText {
struct Line {
  char value[27]{};
  ~Line(){wipe(value,sizeof(value));}
};

class Rows {
  Line visible_[5],empty_;size_t first_=0,count_=0;
 public:
  explicit Rows(size_t first=0):first_(first){}
  void reset(size_t first){for(auto& line:visible_)wipe(line.value,sizeof(line.value));first_=first;count_=0;}
  void push_back(const Line& line){if(count_>=first_&&count_-first_<5)visible_[count_-first_]=line;++count_;}
  size_t size()const{return count_;}size_t first()const{return first_;}
  const Line& operator[](size_t absolute)const{return absolute>=first_&&absolute-first_<5?visible_[absolute-first_]:empty_;}
};

inline char glyph(unsigned char c){if(c>=32&&c<127)return char(c);if(c>=0xc0)return '?';if(c=='\t'||c=='\r')return ' ';return 0;}
inline void append(Rows& rows,const char* first,const char* second="",const char* third=""){
  Line line;size_t n=0;
  for(const char* part:{first,second,third})for(const unsigned char* p=reinterpret_cast<const unsigned char*>(part?part:"");*p;p++){
    if(*p=='\n'){rows.push_back(line);wipe(line.value,sizeof(line.value));n=0;continue;}
    char c=glyph(*p);if(!c)continue;
    if(n==26){rows.push_back(line);wipe(line.value,sizeof(line.value));n=0;}
    line.value[n++]=c;
  }
  rows.push_back(line);
}
}

#endif
