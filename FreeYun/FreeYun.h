#pragma once
#include <ACEBase.h>
#include <string>
#include "HttpClient.h"
#include <nlohmann/json.hpp>
#include <nlohmann/fifo_map.hpp>

//*	传入的初始化信息
typedef struct ANTI_FREEYUN_INIT_INFO
{
	std::string Version;	    //当前版本号
	std::string SecretKey;	    //软件密钥
	std::string Rc4Key;		    //Rc4密钥
	std::string SaltKey;	    //签名盐
	std::string AppId;		    //软件ID
	std::string MachineID;		//机器码
	int   ServerLine;	        //服务器线路

	ANTI_FREEYUN_INIT_INFO(std::string Version, std::string SecretKey, std::string Rc4Key, std::string SaltKey, std::string AppId, std::string MachineID,int ServerLine)
	{	
		this->AppId      = AppId;
		this->Version    = Version;
		this->SecretKey  = SecretKey;
		this->Rc4Key     = Rc4Key;
		this->MachineID  = MachineID;
		this->SaltKey    = SaltKey;
		
		this->ServerLine = ServerLine;
	}
}TAG_ANTI_FREEYUN_INIT_INFO, * PTAG_ANTI_FREEYUN_INIT_INFO;



class FreeYun
{
public:
	bool CloudInit(PTAG_ANTI_FREEYUN_INIT_INFO pInfo);
	
	//取错误码
	int GetErrorCode();
	//取错误信息
	std::string GetErrorStr(int ErrorCode);

private:
	// @ RC4加密
	std::string RC4Encrypt(std::string plaintext);
	// @ RC4解密
	std::string RC4Decode(std::string Ciphertext);
	// @ MD5字符串加密
	std::string GetStrMd5(std::string str);
	// @ post
	std::string Post(std::string str);
private:
	// 可考虑加密这些字符串.但是会带来解密开销
	std::string m_Version;
	std::string m_SecretKey;
	std::string m_Rc4Key;
	std::string m_SaltKey;
	std::string m_AppId;
	std::string m_MachineID;
	ULONG		m_ServerLine;
	HttpClient  m_HttpClient;
	int	        m_ErrorCode;


	//禁止JSON排序
	template<class K, class V, class dummy_compare, class A>
	using my_workaround_fifo_map = nlohmann::fifo_map<K, V, nlohmann::fifo_map_compare<K>, A>;
	using FreeYun_json = nlohmann::basic_json<my_workaround_fifo_map>;

};

