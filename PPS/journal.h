#ifndef PPS_PROJECT_JOURNAL_H_INCLUDED
#define PPS_PROJECT_JOURNAL_H_INCLUDED

#include <cstdint>
#include <cstring>
namespace Journal {
constexpr uint32_t MAGIC=0x324a5050;
struct Ref {uint32_t slot,generation,length;uint8_t digest[32];};
struct Head {uint32_t magic;Ref current,previous;};
template<class IO> bool publish(IO& io,const uint8_t* bytes,size_t n,const Ref& next,const Head& old,Head& committed){
  if(next.slot>1||(old.magic==MAGIC&&next.slot==old.current.slot))return false;
  if(!io.writeSlot(next.slot,bytes,n)||!io.verifySlot(next))return false;
  Head wanted{};wanted.magic=MAGIC;wanted.current=next;
  if(old.magic==MAGIC)wanted.previous=old.current;
  io.writeHead(wanted);
  Head actual{};if(!io.readHead(actual)||memcmp(&actual,&wanted,sizeof(actual)))return false;
  committed=actual;return true;
}
}

#endif
