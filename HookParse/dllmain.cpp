// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"
using json = nlohmann::json;

using pBody = ULONG_PTR * (__fastcall*)(void*);
using pParams = char(__fastcall*)(void*, ULONG_PTR*, ULONG_PTR*);
using pParams2 = void(__fastcall*)(void*, ULONG_PTR*, ULONG_PTR*);

PVOID oriBody = nullptr;
PVOID oriParams = nullptr;
PVOID oriParams2 = nullptr;

static httplib::Server svr;

static json jsonresult;

void FilterJson(std::string& cid, std::string& liveuuid, std::string& title, std::string& playurl)
{
    for (auto& obj : jsonresult)
    {
        if (obj["cid"] == cid)
        {
            for (auto& record : obj["records"])
            {
                if (record["liveUuid"] == liveuuid)
                {
                    record["title"] = title;
                    record["playUrl"] = playurl;
                    return;
                }

            }
            json record;
            record["liveUuid"] = liveuuid;
            record["title"] = title;
            record["playUrl"] = playurl;
            obj["records"].push_back(record);

            return;
        }
    }
    // 不存在cid
    {
        json jsonObject;
        jsonObject["cid"] = cid;
        jsonObject["records"] = json::array();

        json record;
        record["liveUuid"] = liveuuid;
        record["title"] = title;
        record["playUrl"] = playurl;
        jsonObject["records"].push_back(record);

        jsonresult.push_back(jsonObject);

    }

}

ULONG_PTR* __fastcall myBody(void* _this)
{
    //ULONG_PTR* _field = reinterpret_cast<ULONG_PTR*>((ULONG_PTR)_this + 0x50);

    ULONG_PTR* body = reinterpret_cast<pBody>(oriBody)(_this); // ret value
    BYTE _check = *(reinterpret_cast<LPBYTE>(body) + 0x18);
    //printf("%llx %llx %x \r\n", (ULONG_PTR)body , *body, _check);
    //printf("%llx \r\n", (const char*)*body);
    if (_check >= 0x10)
    {
        //printf("run parse \r\n");
        auto _str = reinterpret_cast<const char*>((*body));
        if (*_str == 0x5B || *_str == 0x7B) //   '[' or  '{'  to filter json text
            printf("%s\r\n", _str);
    }

    return body;
}

char __fastcall myParams(void* _this, ULONG_PTR* objInfo0, ULONG_PTR* objInfo1)
{
    /*

    [[rdx]+ 0x108] = URI
    [[rdx]+ 0x50] = reqbody
    [[rdx]+ 0x68] = check
    [[r8]+ 0x50] = respbody

    */
    printf("run hook point\r\n");

    ULONG_PTR* _uri_offset0 = reinterpret_cast<ULONG_PTR*>(*objInfo0 + 0x108);
    const char* _uri = reinterpret_cast<const char*>(*_uri_offset0);

    LPBYTE _check = reinterpret_cast<LPBYTE>(*objInfo0 + 0x68);

    printf("%s %x \r\n ", _uri, (*_check));
    if (*_check >= 0x10)
    {
        printf("run parse\r\n");
        ULONG_PTR* _body_offset0 = reinterpret_cast<ULONG_PTR*>(*objInfo0 + 0x50);
        const char* _body = reinterpret_cast<const char*>(*_body_offset0);
        //if (*_body == 0x5B || *_body == 0x7B) //   '[' or  '{'  to filter json text
        printf("%s\r\n", _body);
    }


    return reinterpret_cast<pParams>(oriParams)(_this, objInfo0, objInfo1);
}

void __fastcall myParams2(void* _this, ULONG_PTR* objInfo0, ULONG_PTR* objInfo1)
{
    /*
    00000223B0505428  00000223ADB30C50  P.³.#...  "/r/Adaptor/LiveRecord/listLiveRecords"

    [[rdx]+ 0x138] = URI
    [[rdx]+ 0x58] = reqbody
    [[rdx]+ 0x70] = check
    [[r8]+ 0x58] = respbody

    */
    //printf("run hook point\r\n");

    ULONG_PTR* _uri_offset0 = reinterpret_cast<ULONG_PTR*>(*objInfo0 + 0x138);
    const char* _uri = reinterpret_cast<const char*>(*_uri_offset0);

    LPBYTE _check = reinterpret_cast<LPBYTE>(*objInfo0 + 0x70);

    if (*_check >= 0x10 && !memcmp((void*)_uri, "/r/Adaptor/LiveRecord/listLiveRecords", 0x25))
    {
        printf("%s %x \r\n ", _uri, (*_check));
        ULONG_PTR* _reqbody_offset0 = reinterpret_cast<ULONG_PTR*>(*objInfo0 + 0x58);
        const char* _reqbody = reinterpret_cast<const char*>(*_reqbody_offset0);

        ULONG_PTR* _respbody_offset0 = reinterpret_cast<ULONG_PTR*>(*objInfo1 + 0x58);
        const char* _respbody = reinterpret_cast<const char*>(*_respbody_offset0);
        if (*_respbody == 0x5B || *_respbody == 0x7B) //   '[' or  '{'  to filter json text
        {
            auto unicodeString = std::string(_respbody);
            json j = json::parse(unicodeString);
            for (const auto& obj : j["records"])
            {
                std::string _liveUuid = obj["liveUuid"].get<std::string>();
                std::string _cid = obj["cid"].get<std::string>();
                std::string _title = obj["title"].get<std::string>();
                std::string _url = obj["playUrl"].get<std::string>();
                FilterJson(_cid, _liveUuid, _title, _url);
            }

        }
    }


    return reinterpret_cast<pParams2>(oriParams2)(_this, objInfo0, objInfo1);
}
void HttpServer()
{
    svr.Get("/list", [](const httplib::Request&, httplib::Response& res) {

        res.set_content(jsonresult.dump(), "application/json");
        });


    svr.listen("0.0.0.0", 52101);
}
BOOL HookIns()
{
    AllocConsole();
    FILE* fp;
    freopen_s(&fp, "CONOUT$", "w", stdout);

    ULONG_PTR hMod = (ULONG_PTR)GetModuleHandleA("libgaea.dll");

    //oriBody = (PVOID)(hMod + 0x2B7B40);

    // same as below but only get request body
    // oriParams = (PVOID)(hMod + 0x33C490);

    // better hook point both reqbody and respbody
    oriParams2 = (PVOID)(hMod + 0x33AC60);

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());


    /*DetourAttach(&oriBody,
        &myBody);*/

    DetourAttach(&oriParams2,
        &myParams2);


    LONG hRet = DetourTransactionCommit();

    if (hRet == NO_ERROR)
    {
        std::thread(HttpServer).detach();
        return TRUE;
    }
    else
        return FALSE;

}
BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{


    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        std::thread(HookIns).detach();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

