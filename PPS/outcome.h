#ifndef PPS_PROJECT_OUTCOME_H_INCLUDED
#define PPS_PROJECT_OUTCOME_H_INCLUDED

enum class Outcome {Ok,Invalid,Conflict,Credentials,Storage,Corrupt,Unavailable,Throttled,NoPrevious,NoMemory};
inline const char* outcomeCode(Outcome r){
  switch(r){
    case Outcome::NoMemory:return "memory_unavailable";
    case Outcome::Ok:return "ok";
    case Outcome::Invalid:return "invalid_request";
    case Outcome::Conflict:return "revision_conflict";
    case Outcome::Credentials:return "invalid_credentials";
    case Outcome::Storage:return "storage_error";
    case Outcome::Corrupt:return "vault_corrupt";
    case Outcome::Unavailable:return "unavailable";
    case Outcome::Throttled:return "rate_limited";
    case Outcome::NoPrevious:return "no_previous_snapshot";
  }
  return "internal_error";
}
inline int outcomeStatus(Outcome r){
  switch(r){
    case Outcome::Ok:return 200;
    case Outcome::Invalid:return 400;
    case Outcome::Credentials:return 403;
    case Outcome::Conflict:return 409;
    case Outcome::Throttled:return 429;
    case Outcome::NoPrevious:return 404;
    case Outcome::NoMemory:case Outcome::Unavailable:return 503;
    default:return 500;
  }
}

#endif
