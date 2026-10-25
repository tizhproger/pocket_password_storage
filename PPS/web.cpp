#include "web.h"
#include "pps_tls_override.h"
#include "web_assets.h"
#include "app.h"
#include "pps_network.h"
#include "crypto.h"
#include <Preferences.h>
#include <esp_https_server.h>
#include <esp_idf_version.h>
#include <mbedtls/pk.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/x509.h>
#include <mbedtls/ecp.h>
#include <mbedtls/version.h>
#ifdef ARDUINO_ARCH_ESP32
#include <esp_arduino_version.h>
#include <esp_system.h>
#endif
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>
namespace Web {
static Bytes certificate,privateKey;
static String certFingerprint;
static httpd_handle_t server=nullptr;
struct Job {httpd_req_t* request;SemaphoreHandle_t done;esp_err_t result;};
static Job* pending=nullptr;
static bool accepting=false;
static portMUX_TYPE mux=portMUX_INITIALIZER_UNLOCKED;
static bool identity(){
  Preferences p;if(!p.begin("ppstls",false))return false;
  if(p.isKey("identity")){
    size_t n=p.getBytesLength("identity");if(n<100||n>6000)return false;Bytes b(n);if(!b.valid()||p.getBytes("identity",b.data(),n)!=n)return false;
    uint16_t cn,kn;memcpy(&cn,b.data(),2);memcpy(&kn,b.data()+2,2);if(size_t(cn)+kn+4!=n||!cn||!kn)return false;
    if(!certificate.assign(b.begin()+4,b.begin()+4+cn)||!privateKey.assign(b.begin()+4+cn,b.end()))return false;
  }else{
    mbedtls_pk_context key;mbedtls_pk_init(&key);mbedtls_x509write_cert crt;mbedtls_x509write_crt_init(&crt);
    int rc=mbedtls_pk_setup(&key,mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
    if(!rc)rc=mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1,mbedtls_pk_ec(key),Crypto::rng,nullptr);
    Secret<16> randomSerial;if(!Crypto::random(randomSerial.data,16))rc=-1;randomSerial.data[0]=(randomSerial.data[0]&0x7f)|1;
    mbedtls_x509write_crt_set_version(&crt,MBEDTLS_X509_CRT_VERSION_3);mbedtls_x509write_crt_set_md_alg(&crt,MBEDTLS_MD_SHA256);
    mbedtls_x509write_crt_set_subject_key(&crt,&key);mbedtls_x509write_crt_set_issuer_key(&crt,&key);
    if(!rc)rc=PpsMbedTls::setSerial(&crt,randomSerial.data,16);
    if(!rc)rc=mbedtls_x509write_crt_set_subject_name(&crt,"CN=pps.local,O=PPS");
    if(!rc)rc=mbedtls_x509write_crt_set_issuer_name(&crt,"CN=pps.local,O=PPS");
    if(!rc)rc=mbedtls_x509write_crt_set_validity(&crt,"20260101000000","20360101000000");
    if(!rc)rc=mbedtls_x509write_crt_set_basic_constraints(&crt,0,-1);
    if(!rc)rc=mbedtls_x509write_crt_set_key_usage(&crt,MBEDTLS_X509_KU_DIGITAL_SIGNATURE);
    const unsigned char san[]={0x30,0x11,0x82,0x09,'p','p','s','.','l','o','c','a','l',0x87,0x04,192,168,4,1};
    if(!rc)rc=mbedtls_x509write_crt_set_extension(&crt,"\x55\x1d\x11",3,0,san,sizeof(san));
    Bytes buf(2048);if(!buf.valid())rc=-1;int cn=rc?rc:mbedtls_x509write_crt_der(&crt,buf.data(),buf.size(),Crypto::rng,nullptr);
    if(cn<=0||!certificate.assign(buf.end()-cn,buf.end()))rc=-1;
    int kn=rc?rc:mbedtls_pk_write_key_der(&key,buf.data(),buf.size());if(kn<=0||!privateKey.assign(buf.end()-kn,buf.end()))rc=-1;
    mbedtls_x509write_crt_free(&crt);mbedtls_pk_free(&key);if(rc)return false;
    uint16_t cs=certificate.size(),ks=privateKey.size();Bytes all(4+cs+ks);if(!all.valid())return false;memcpy(all.data(),&cs,2);memcpy(all.data()+2,&ks,2);memcpy(all.data()+4,certificate.data(),cs);memcpy(all.data()+4+cs,privateKey.data(),ks);
    p.putBytes("identity",all.data(),all.size());size_t n=p.getBytesLength("identity");if(n!=all.size())return false;
    Bytes check(n);if(!check.valid()||p.getBytes("identity",check.data(),n)!=n||!Crypto::equal(all.data(),check.data(),n))return false;
  }
  if(!PpsTls::selectCertificate(certificate,privateKey,Crypto::rng,nullptr)){
    Bytes().swap(certificate);Bytes().swap(privateKey);certFingerprint=String();
    return false;
  }
  mbedtls_x509_crt crt;mbedtls_x509_crt_init(&crt);mbedtls_pk_context key;mbedtls_pk_init(&key);
  bool ok=mbedtls_x509_crt_parse_der(&crt,certificate.data(),certificate.size())==0&&PpsMbedTls::parseKey(&key,privateKey.data(),privateKey.size(),Crypto::rng,nullptr)==0&&PpsMbedTls::checkPair(&crt.pk,&key,Crypto::rng,nullptr)==0;
  mbedtls_pk_free(&key);mbedtls_x509_crt_free(&crt);Secret<32> digest;
  if(!ok||!Crypto::hash(certificate.data(),certificate.size(),digest.data))return false;certFingerprint=Crypto::hex(digest.data,32);return certFingerprint.length()==64;
}
bool begin(){if(identity())return true;certificate.clear();privateKey.clear();wipe(certFingerprint);return false;}
String fingerprint(){return certFingerprint;}
static String header(httpd_req_t* r,const char* name){
  size_t n=httpd_req_get_hdr_value_len(r,name);if(!n||n>1024)return String();Bytes b(n+1);if(!b.valid())return String();
  if(httpd_req_get_hdr_value_str(r,name,reinterpret_cast<char*>(b.data()),b.size())!=ESP_OK){PpsMemory::failed();return String();}
  String out(reinterpret_cast<char*>(b.data()));if(out.length()!=n){PpsMemory::failed();wipe(out);}return out;
}
static bool securityHeaders(httpd_req_t* r){
  return httpd_resp_set_hdr(r,"Cache-Control","no-store")==ESP_OK&&httpd_resp_set_hdr(r,"Pragma","no-cache")==ESP_OK&&httpd_resp_set_hdr(r,"X-Content-Type-Options","nosniff")==ESP_OK&&
    httpd_resp_set_hdr(r,"X-Frame-Options","DENY")==ESP_OK&&httpd_resp_set_hdr(r,"Referrer-Policy","no-referrer")==ESP_OK&&httpd_resp_set_hdr(r,"Connection","close")==ESP_OK&&
    httpd_resp_set_hdr(r,"Content-Security-Policy","default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")==ESP_OK;
}
static const char* statusText(int code){switch(code){case 200:return "200 OK";case 400:return "400 Bad Request";case 401:return "401 Unauthorized";case 403:return "403 Forbidden";case 404:return "404 Not Found";case 409:return "409 Conflict";case 413:return "413 Payload Too Large";case 429:return "429 Too Many Requests";case 503:return "503 Service Unavailable";default:return "500 Internal Server Error";}}
static esp_err_t send(httpd_req_t* r,int code,const char* type,const void* p,size_t n){if(httpd_resp_set_status(r,statusText(code))!=ESP_OK||httpd_resp_set_type(r,type)!=ESP_OK)return ESP_FAIL;return httpd_resp_send(r,static_cast<const char*>(p),n);}
static esp_err_t noMemory(httpd_req_t* r){
  static const char failure[]="{\"ok\":false,\"error\":\"memory_unavailable\",\"message\":\"Low memory; close other connections, reload and check the result before retrying\"}";
  return send(r,503,"application/json; charset=utf-8",failure,sizeof(failure)-1);
}
static esp_err_t json(httpd_req_t* r,const SecureJson& doc,int code=200){
  PpsMemory::Attempt memory;Bytes b;if(!serializeChecked(doc,b,Config::REQUEST_MAX)){if(memory.failed())return noMemory(r);static const char failure[]="{\"ok\":false,\"error\":\"serialization_error\",\"message\":\"Response serialization failed\"}";return send(r,500,"application/json; charset=utf-8",failure,sizeof(failure)-1);}
  return send(r,code,"application/json; charset=utf-8",b.data(),b.size()-1);
}
static esp_err_t result(httpd_req_t* r,int code,const char* msg,const char* error=nullptr){
  SecureJson doc(1024);doc["ok"]=code==200;doc["message"]=msg;
  doc["error"]=error?error:code==200?"ok":code==400?"invalid_request":code==401?"session_expired":code==409?"revision_conflict":code==429?"rate_limited":code==500?"storage_error":"request_rejected";
  return json(r,doc,code);
}
static esp_err_t operation(httpd_req_t* r,Outcome outcome,const char* success){if(outcome==Outcome::NoMemory)return noMemory(r);return result(r,outcomeStatus(outcome),outcome==Outcome::Ok?success:outcomeCode(outcome),outcomeCode(outcome));}
static bool fields(JsonVariantConst doc,std::initializer_list<const char*> names){
  if(!doc.is<JsonObjectConst>()||doc.size()!=names.size())return false;
  for(auto name:names)if(doc[name].isUnbound())return false;return true;
}
static bool body(httpd_req_t* r,SecureJson& doc,size_t limit){
  String type=header(r,"Content-Type"),cl=header(r,"Content-Length");
  if(type!="application/json"&&strncmp(type.c_str(),"application/json;",17)!=0)return false;
  if(!cl.length()||cl.length()>6||header(r,"Transfer-Encoding").length())return false;
  size_t declared=0;for(size_t i=0;i<cl.length();i++){if(cl[i]<'0'||cl[i]>'9')return false;declared=declared*10+cl[i]-'0';}
  if(!declared||declared!=r->content_len||declared>limit)return false;
  Bytes b(declared);if(!b.valid())return false;size_t got=0;uint64_t deadline=App::now()+5000;
  while(got<b.size()&&App::now()<deadline){int n=httpd_req_recv(r,reinterpret_cast<char*>(b.data()+got),b.size()-got);if(n<=0)return false;got+=n;}
  return got==b.size()&&deserializeChecked(doc,b.data(),b.size())&&doc.is<JsonObject>();
}
static bool textField(JsonVariantConst v,size_t max){if(!v.is<const char*>())return false;auto s=v.as<JsonString>();return s.size()<=max&&s.size()==strlen(s.c_str());}
static esp_err_t dispatch(httpd_req_t* r){
  PpsMemory::Attempt memory;if(!securityHeaders(r))return ESP_FAIL;
  String host=header(r,"Host"),origin=header(r,"Origin"),ip=Net::ip();if(memory.failed()||!ip.length())return noMemory(r);
  if(httpd_req_get_hdr_value_len(r,"Origin")>1024||httpd_req_get_hdr_value_len(r,"Host")>1024)return result(r,403,"Header too long");
  char ipHost[48],ipOrigin[64],ipOriginPort[68];snprintf(ipHost,sizeof(ipHost),"%s:443",ip.c_str());snprintf(ipOrigin,sizeof(ipOrigin),"https://%s",ip.c_str());snprintf(ipOriginPort,sizeof(ipOriginPort),"https://%s:443",ip.c_str());
  bool hostOK=host=="pps.local"||host=="pps.local:443"||host==ip||host==ipHost;
  bool originOK=!origin.length()||origin=="https://pps.local"||origin=="https://pps.local:443"||origin==ipOrigin||origin==ipOriginPort;
  if(!hostOK||!originOK)return result(r,403,"Host or Origin rejected");
  SecretString route(r->uri);if(memory.failed())return noMemory(r);const String& path=route.value;bool get=r->method==HTTP_GET;
  if(get){
    if(path=="/"||path=="/index.html"||path=="/login.html"||path=="/init.html"||path=="/settings.html")return send(r,200,"text/html; charset=utf-8",WEB_INDEX,sizeof(WEB_INDEX)-1);
    if(path=="/script.js")return send(r,200,"application/javascript; charset=utf-8",WEB_SCRIPT,sizeof(WEB_SCRIPT)-1);
    if(path=="/style.css")return send(r,200,"text/css; charset=utf-8",WEB_STYLE,sizeof(WEB_STYLE)-1);
    if(path=="/device.crt")return send(r,200,"application/pkix-cert",certificate.data(),certificate.size());
    if(path=="/api/status"){SecureJson out(1024);out["state"]=Vault::stateName();out["setup_ready"]=App::setupReady();out["version"]=Config::VERSION;out["max_entries"]=Config::MAX_ENTRIES;out["vault_max_bytes"]=Config::VAULT_MAX;return json(r,out);}
  }
  bool publicPost=!get&&(path=="/api/login"||path=="/api/setup");
  SecretString bearer(header(r,"Authorization"));SecretString token(!strncmp(bearer.value.c_str(),"Bearer ",7)?bearer.value.c_str()+7:"");
  if(memory.failed())return noMemory(r);
  if(!publicPost&&!App::authorized(token.value))return result(r,401,"Sign in required");
  bool simple=!get&&(path=="/api/logout"||path=="/api/lock"||path=="/api/touch"||path=="/api/apply");
  bool entry=!get&&(path=="/api/add"||path=="/api/edit");
  bool known=get?(path=="/api/settings"||path=="/api/records"||path=="/api/diagnostics"):(publicPost||simple||entry||path=="/api/settings"||path=="/api/master"||path=="/api/restore"||path=="/api/import"||path=="/api/delete");
  if(!known)return result(r,404,"Not found");if(publicPost&&App::waitSeconds(false))return operation(r,Outcome::Throttled,"");
  size_t limit=publicPost||path=="/api/restore"?1536:simple?256:path=="/api/delete"?384:entry||path=="/api/import"?Config::REQUEST_MAX:2048;
  size_t budget=get?0:publicPost?4096:simple||path=="/api/delete"?2048:path=="/api/import"?Config::JSON_CAPACITY:entry?16384:6144;
  SecureJson input(budget);
  if(!get){if(r->content_len>limit)return result(r,413,"Request too large");if(!body(r,input,limit))return memory.failed()?noMemory(r):result(r,400,"Invalid JSON request");}
  if(!get&&(path=="/api/login"||path=="/api/setup")){
    if(!(path=="/api/login"?fields(input.as<JsonVariantConst>(),{"password"}):fields(input.as<JsonVariantConst>(),{"password","code"}))||!textField(input["password"],128))return result(r,400,"Invalid password field");if(App::waitSeconds(false))return result(r,429,"Wait before retrying");
    SecretString password(input["password"].as<const char*>());if(memory.failed())return noMemory(r);
    if(path=="/api/setup"){
      if(!textField(input["code"],8))return result(r,400,"Invalid setup code");
      SecretString code(input["code"].as<const char*>());if(memory.failed())return noMemory(r);bool ok=App::setup(password.value,code.value);if(!ok&&(memory.failed()||App::lastResult()==Outcome::NoMemory))return noMemory(r);return result(r,ok?200:403,ok?"Setup complete; sign in":"Setup or migration failed; check device state",ok?"ok":"setup_failed");
    }
    SecretString token(App::login(password.value));if(!token.value.length())return operation(r,App::lastResult(),"");SecureJson out(512);out["token"]=token.value;return json(r,out);
  }
  if(simple&&!fields(input.as<JsonVariantConst>(),{}))return result(r,400,"Unexpected fields");
  if(path=="/api/logout"&&!get){App::logout(token.value);return result(r,200,"Signed out");}
  if(path=="/api/diagnostics"&&get){
    SecureJson out(4096);out["firmware"]=Config::VERSION;out["arduinojson"]=ARDUINOJSON_VERSION;out["mbedtls"]=MBEDTLS_VERSION_STRING;
    out["tls_sdk_review_required"]=MBEDTLS_VERSION_NUMBER<0x03060700;out["max_entries"]=Config::MAX_ENTRIES;out["vault_max_bytes"]=Config::VAULT_MAX;out["json_budget_bytes"]=Config::JSON_CAPACITY;
    out["allocation_failures"]=PpsMemory::failures.load(std::memory_order_relaxed);
#ifdef ARDUINO_ARCH_ESP32
    out["arduino_core"]=ESP_ARDUINO_VERSION_STR;out["esp_idf"]=esp_get_idf_version();out["heap_free"]=heap_caps_get_free_size(MALLOC_CAP_8BIT);out["heap_min"]=heap_caps_get_minimum_free_size(MALLOC_CAP_8BIT);out["heap_largest_block"]=heap_caps_get_largest_free_block(MALLOC_CAP_8BIT);
#endif
    return json(r,out);
  }
  if(path=="/api/lock"&&!get){App::lock();return result(r,200,"Locked");}
  if(path=="/api/touch"&&!get)return result(r,200,"OK");
  if(path=="/api/settings"){
    if(get){SecureJson out(4096);Net::settings(out);return json(r,out);}
    return operation(r,Net::save(input.as<JsonVariantConst>()),"Saved; apply separately");
  }
  if(path=="/api/apply"&&!get)return operation(r,Net::queueApply(),"Reconnecting; sign in again");
  if(path=="/api/master"&&!get){
    if(!fields(input.as<JsonVariantConst>(),{"old_password","new_password"})||!textField(input["old_password"],128)||!textField(input["new_password"],128))return result(r,400,"Invalid password fields");
    if(App::waitSeconds(false))return result(r,429,"Wait before retrying");SecretString old(input["old_password"].as<const char*>()),next(input["new_password"].as<const char*>());if(memory.failed())return noMemory(r);return operation(r,App::changeMaster(old.value,next.value),"Password changed; all sessions locked");
  }
  if(path=="/api/restore"&&!get){
    if(!fields(input.as<JsonVariantConst>(),{"revision","password","confirm_replace"})||!textField(input["revision"],64)||!textField(input["password"],128)||!input["confirm_replace"].is<bool>()||!input["confirm_replace"].as<bool>())return result(r,400,"Explicit confirmation and current password required");
    String currentRevision=Vault::revision();if(memory.failed())return noMemory(r);if(strcmp(input["revision"].as<const char*>(),currentRevision.c_str()))return operation(r,Outcome::Conflict,"");
    SecretString password(input["password"].as<const char*>());if(memory.failed())return noMemory(r);return operation(r,App::restorePrevious(password.value),"Previous data restored; all sessions locked");
  }
  if(path=="/api/records"&&get){SecureJson out(Config::JSON_CAPACITY);if(!Vault::read(out))return operation(r,Vault::lastResult(),"");String rev=Vault::revision();if(memory.failed())return noMemory(r);if(httpd_resp_set_hdr(r,"X-Vault-Revision",rev.c_str())!=ESP_OK)return ESP_FAIL;return json(r,out);}
  if(!get&&(path=="/api/add"||path=="/api/edit"||path=="/api/delete"||path=="/api/import")){
    bool shape=path=="/api/import"?fields(input.as<JsonVariantConst>(),{"revision","data","legacy","confirm_replace"}):path=="/api/delete"?fields(input.as<JsonVariantConst>(),{"revision","id"}):path=="/api/add"?fields(input.as<JsonVariantConst>(),{"revision","entry"}):fields(input.as<JsonVariantConst>(),{"revision","id","entry"});
    if(!shape)return result(r,400,"Unexpected or missing fields");
    if(!textField(input["revision"],64))return result(r,400,"Invalid revision");String currentRevision=Vault::revision();if(memory.failed())return noMemory(r);if(strcmp(input["revision"].as<const char*>(),currentRevision.c_str()))return result(r,409,"Vault changed; reload and review your edit");
    if(path=="/api/import"){
      if(!input["confirm_replace"].is<bool>()||!input["confirm_replace"].as<bool>()||!input["legacy"].is<bool>())return result(r,400,"Invalid import");bool ok;
      if(input["legacy"].as<bool>()){
        SecureJson converted(Config::JSON_CAPACITY);if(!Vault::importEntries(input["data"],converted,true))return memory.failed()?noMemory(r):result(r,400,"Invalid import");input.clear();ok=Vault::save(converted);
      }else{
        if(!Vault::validate(input["data"]))return result(r,400,"Invalid import");JsonArray importedEntries=input["data"]["entries"].as<JsonArray>();
        for(auto e:importedEntries){String id=Crypto::token(16);if(id.length()!=32)return memory.failed()?noMemory(r):operation(r,Outcome::Unavailable,"");e["id"]=id;}
        if(input.overflowed())return noMemory(r);ok=Vault::save(input["data"].as<JsonVariantConst>());
      }return ok?result(r,200,"Saved"):operation(r,Vault::lastResult(),"");
    }
    SecureJson doc(Config::JSON_CAPACITY);if(!Vault::read(doc))return operation(r,Vault::lastResult(),"");auto entries=doc["entries"].as<JsonArray>();
    if(path=="/api/add"){
      auto e=input["entry"].as<JsonObject>();if(e.isNull()||e.size()!=4||entries.size()>=Config::MAX_ENTRIES)return result(r,400,"Invalid entry or limit reached");
      String id=Crypto::token(16);if(id.length()!=32)return memory.failed()?noMemory(r):operation(r,Outcome::Unavailable,"");auto dest=jsonAddObject(entries);dest.set(e);dest["id"]=id;
    }else{
      if(!textField(input["id"],32))return result(r,400,"Invalid id");int index=-1;
      for(size_t i=0;i<entries.size();i++)if(!strcmp(input["id"].as<const char*>(),entries[i]["id"].as<const char*>()))index=i;
      if(index<0)return result(r,409,"Entry no longer exists");
      if(path=="/api/delete")entries.remove(index);else{if(!textField(input["entry"]["id"],32)||strcmp(input["entry"]["id"].as<const char*>(),input["id"].as<const char*>()))return result(r,400,"Entry id mismatch");entries[index].set(input["entry"]);}
    }
    if(doc.overflowed())return noMemory(r);
    if(!Vault::validate(doc.as<JsonVariantConst>()))return result(r,400,"Invalid data or size limit");
    return Vault::save(doc)?result(r,200,"Saved"):operation(r,Vault::lastResult(),"");
  }
  return result(r,404,"Not found");
}
static esp_err_t enqueue(httpd_req_t* r){
  Job job{r,xSemaphoreCreateBinary(),ESP_FAIL};if(!job.done)return ESP_FAIL;
  portENTER_CRITICAL(&mux);bool queued=accepting&&!pending;if(queued)pending=&job;portEXIT_CRITICAL(&mux);
  if(queued)xSemaphoreTake(job.done,portMAX_DELAY);vSemaphoreDelete(job.done);return job.result;
}
bool start(){
  if(server)return true;if(certificate.empty()||privateKey.empty())return false;
  httpd_ssl_config_t config=HTTPD_SSL_CONFIG_DEFAULT();
  config.session_tickets=false; // CVE-2026-50586 workaround.
#if ESP_IDF_VERSION_MAJOR >= 5
  config.servercert=certificate.data();config.servercert_len=certificate.size();
#else
  config.cacert_pem=certificate.data();config.cacert_len=certificate.size();
#endif
  config.prvtkey_pem=privateKey.data();config.prvtkey_len=privateKey.size();
  config.httpd.max_open_sockets=2;config.httpd.max_uri_handlers=4;config.httpd.max_resp_headers=12;config.httpd.recv_wait_timeout=2;config.httpd.send_wait_timeout=2;config.httpd.lru_purge_enable=true;config.httpd.uri_match_fn=httpd_uri_match_wildcard;
  if(httpd_ssl_start(&server,&config)!=ESP_OK){server=nullptr;return false;}
  httpd_uri_t get{};get.uri="/*";get.method=HTTP_GET;get.handler=enqueue;httpd_uri_t post=get;post.method=HTTP_POST;
  if(httpd_register_uri_handler(server,&get)!=ESP_OK||httpd_register_uri_handler(server,&post)!=ESP_OK){httpd_ssl_stop(server);server=nullptr;return false;}
  portENTER_CRITICAL(&mux);accepting=true;portEXIT_CRITICAL(&mux);return true;
}
void stop(){
  portENTER_CRITICAL(&mux);accepting=false;Job* j=pending;pending=nullptr;portEXIT_CRITICAL(&mux);
  if(j){j->result=ESP_FAIL;xSemaphoreGive(j->done);}if(server){httpd_ssl_stop(server);server=nullptr;}
}
void tick(){
  portENTER_CRITICAL(&mux);Job* job=pending;pending=nullptr;portEXIT_CRITICAL(&mux);if(!job)return;
  dispatch(job->request);
  job->result=ESP_FAIL;xSemaphoreGive(job->done);
}
}
