#include "HttpClient.h"

/*
* 4. CURLOPT_USERAGENT
��ѡ��Ҫ�󴫵�һ���� '\0' ��β���ַ���ָ�룬����ַ��������������������ʱ���� HTTP ͷ���е� User-Agent ��Ϣ����Щ����������Ҫ��������Ϣ�ģ����û������ User-Agent����ô�������ܾ��������ú󣬿���ƭ���������Դ˵ļ�顣
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
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 8);//���ӳ�ʱ�������ֵ�������̫�̿��ܵ����������󲻵��ͶϿ���
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10);//��������ʱ��ʱ���ã����10��������δ�����ֱ꣬���˳�
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
		//ȱʡ�������PEM�������������ã�����֧��DER
		//curl_easy_setopt(curl,CURLOPT_SSLCERTTYPE,"PEM");
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, true);
		curl_easy_setopt(curl, CURLOPT_CAINFO, pCaPath);
	}
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 8);//���ӳ�ʱ�������ֵ�������̫�̿��ܵ����������󲻵��ͶϿ���
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10);//��������ʱ��ʱ���ã����10��������δ�����ֱ꣬���˳�
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
	* ������̶߳�ʹ�ó�ʱ�����ʱ��ͬʱ���߳�����sleep����wait�Ȳ�����
	* ������������ѡ�libcurl���ᷢ�źŴ�����wait�Ӷ����³����˳���
	*/
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 8);//���ӳ�ʱ�������ֵ�������̫�̿��ܵ����������󲻵��ͶϿ���
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10);//��������ʱ��ʱ���ã����10��������δ�����ֱ꣬���˳�



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
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 8);//���ӳ�ʱ�������ֵ�������̫�̿��ܵ����������󲻵��ͶϿ���
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10);//��������ʱ��ʱ���ã����10��������δ�����ֱ꣬���˳�
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
