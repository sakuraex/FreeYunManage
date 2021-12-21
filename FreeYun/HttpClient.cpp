#include "HttpClient.h"

/*
* 4. CURLOPT_USERAGENT
该选项要求传递一个以 '\0' 结尾的字符串指针，这个字符串用来在向服务器请求时发送 HTTP 头部中的 User-Agent 信息，有些服务器是需要检测这个信息的，如果没有设置 User-Agent，那么服务器拒绝请求。设置后，可以骗过服务器对此的检查。
*/




CURLcode HttpClient::Post(const std::string& strUrl, const std::string& strPost, std::string& strResponse)
{
	CURLcode res;
	m_Header.clear();
	CURL* curl = curl_easy_init();

	if (NULL == curl)
	{
		return CURLE_FAILED_INIT;
	}
	curl_easy_setopt(curl, CURLOPT_URL, strUrl.c_str());
	curl_easy_setopt(curl, CURLOPT_POST, 1);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, strPost.c_str());
	curl_easy_setopt(curl, CURLOPT_READFUNCTION, NULL);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, OnWriteData);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)&strResponse);
	curl_easy_setopt(curl, CURLOPT_HEADERDATA, &m_Header);
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 8);//连接超时，这个数值如果设置太短可能导致数据请求不到就断开了
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10);//接收数据时超时设置，如果10秒内数据未接收完，直接退出
	res = curl_easy_perform(curl);

	curl_easy_cleanup(curl);

	return res;
}

CURLcode HttpClient::Posts(const std::string& strUrl, const std::string& strPost, std::string& strResponse, const char* pCaPath /*= NULL*/)
{
	CURLcode res;
	m_Header.clear();
	CURL* curl = curl_easy_init();
	if (NULL == curl)
	{
		return CURLE_FAILED_INIT;
	}
	curl_easy_setopt(curl, CURLOPT_URL, strUrl.c_str());
	curl_easy_setopt(curl, CURLOPT_POST, 1);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, strPost.c_str());
	curl_easy_setopt(curl, CURLOPT_READFUNCTION, NULL);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, OnWriteData);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)&strResponse);
	curl_easy_setopt(curl, CURLOPT_HEADERDATA, &m_Header);
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);
	if (NULL == pCaPath)
	{
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, false);
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, false);
	}
	else
	{
		//缺省情况就是PEM，所以无需设置，另外支持DER
		//curl_easy_setopt(curl,CURLOPT_SSLCERTTYPE,"PEM");
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, true);
		curl_easy_setopt(curl, CURLOPT_CAINFO, pCaPath);
	}
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 8);//连接超时，这个数值如果设置太短可能导致数据请求不到就断开了
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10);//接收数据时超时设置，如果10秒内数据未接收完，直接退出
	res = curl_easy_perform(curl);
	curl_easy_cleanup(curl);
	return res;
}



CURLcode HttpClient::Get(const std::string& strUrl, std::string& strResponse)
{
	CURLcode res;
	m_Header.clear();
	CURL* curl = curl_easy_init();
	if (NULL   == curl)
	{
		return CURLE_FAILED_INIT;
	}
	curl_easy_setopt(curl, CURLOPT_URL, strUrl.c_str());
	curl_easy_setopt(curl, CURLOPT_READFUNCTION, NULL);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, OnWriteData);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)&strResponse);

	curl_easy_setopt(curl, CURLOPT_HEADERDATA, &m_Header);

	/**
	* 当多个线程都使用超时处理的时候，同时主线程中有sleep或是wait等操作。
	* 如果不设置这个选项，libcurl将会发信号打断这个wait从而导致程序退出。
	*/
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 8);//连接超时，这个数值如果设置太短可能导致数据请求不到就断开了
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10);//接收数据时超时设置，如果10秒内数据未接收完，直接退出



	res        = curl_easy_perform(curl);
	curl_easy_cleanup(curl);
	return res;
}

CURLcode HttpClient::Gets(const std::string& strUrl, std::string& strResponse, const char* pCaPath /*= NULL*/)
{
	CURLcode res;
	m_Header.clear();
	CURL* curl = curl_easy_init();
	if (NULL == curl)
	{
		return CURLE_FAILED_INIT;
	}
	curl_easy_setopt(curl, CURLOPT_URL, strUrl.c_str());
	curl_easy_setopt(curl, CURLOPT_READFUNCTION, NULL);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, OnWriteData);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)&strResponse);
	
	curl_easy_setopt(curl, CURLOPT_HEADERDATA, &m_Header);
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);
	if (NULL == pCaPath)
	{
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, false);
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, false);
	}
	else
	{
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, true);
		curl_easy_setopt(curl, CURLOPT_CAINFO, pCaPath);
	}
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 8);//连接超时，这个数值如果设置太短可能导致数据请求不到就断开了
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10);//接收数据时超时设置，如果10秒内数据未接收完，直接退出
	res = curl_easy_perform(curl);
	curl_easy_cleanup(curl);
	return res;
}

std::string HttpClient::GetErrorStr(CURLcode ErrorCode)
{
	return std::string(curl_easy_strerror(ErrorCode));
}

std::string HttpClient::GetHttpHeader()
{
	return m_Header;
}

size_t HttpClient::OnWriteData(void* buffer, size_t size, size_t nmemb, void* lpVoid)
{
	std::string* str = dynamic_cast<std::string*>((std::string*)lpVoid);
	if (NULL == str || NULL == buffer)
	{
		return -1;
	}

	char* pData = (char*)buffer;
	str->append(pData, size * nmemb);
	return nmemb;
}
