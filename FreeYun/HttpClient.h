#pragma once
#include <curl/curl.h>
#include <string>
#pragma comment(lib,"curl/Win32/lib/libcurl.lib")
#pragma comment(lib,"openssl/win32/lib/libcrypto.lib")
#pragma comment(lib,"openssl/win32/lib/libssl.lib")
#pragma comment(lib,"Crypt32.lib")
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"winmm.lib")
#pragma comment(lib,"wldap32.lib")

class HttpClient
{
public:
	CURLcode Post(const std::string& strUrl, const std::string& strPost, std::string& strResponse);
	CURLcode Posts(const std::string& strUrl, const std::string& strPost, std::string& strResponse, const char* pCaPath = NULL);

	CURLcode Get(const std::string& strUrl, std::string& strResponse);
	CURLcode Gets(const std::string& strUrl, std::string& strResponse, const char* pCaPath = NULL);

	//@取错误代码转字符串
	std::string GetErrorStr(CURLcode ErrorCode);
	//@返回Http头部信息
	std::string GetHttpHeader();



private:
	static size_t OnWriteData(void* buffer, size_t size, size_t nmemb, void* lpVoid);
	std::string m_Header;
};

