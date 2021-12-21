#include "FreeYun.h"
#include <ctime>
#include <ACEConnect.h>
#include "openssl/rc4.h"
#include "openssl/md5.h"


bool FreeYun::CloudInit(PTAG_ANTI_FREEYUN_INIT_INFO pInfo)
{
	VMProtectBegin(__FUNCTION__);

	m_Version    = pInfo->Version;
	m_SecretKey  = pInfo->SecretKey;
	m_Rc4Key     = pInfo->Rc4Key;
	m_SaltKey    = pInfo->SaltKey;
	m_AppId      = pInfo->AppId;
	m_MachineID  = pInfo->MachineID;
	m_ServerLine = pInfo->ServerLine;

	bool result = false;

	auto util = std::make_unique<CACEUtil>();
	// 获取时间戳
	auto csTime = util->GetTimeStampStr();

	// 要发送的数据
	FreeYun_json SendJsonData=
	{
		{ "version"  , m_Version},
		{ "timestamp", csTime },
		{ "macCode"  , m_MachineID},
		{ "secretKey", m_SecretKey}
	};
	//RC4加密发送的数据
	auto RC4SendData =  RC4Encrypt(SendJsonData.dump());
	//封包的签名
	std::string csSendDataToMd5;
	csSendDataToMd5 =  "1";				//请求操作的类型
	csSendDataToMd5 += csTime;			//时间戳
	csSendDataToMd5 += m_SaltKey;		//签名盐
	csSendDataToMd5 += m_AppId;			//aphid
	csSendDataToMd5 += RC4SendData;		//RC4加密的data

	auto StrMd5 = GetStrMd5(csSendDataToMd5);
	std::string SendStr = fmt::format("version={}&appid={}&wtype={}&timestamp={}&data={}&sign={}", m_Version, m_AppId, 1, csTime, RC4SendData, StrMd5);

	auto JsonText =  this->Post(SendStr);

	if (JsonText.empty())
	{

		return false;
	}


	auto j = nlohmann::json::parse(JsonText);



	//auto v1 =  j.at("msg");
	//auto v2 = j.at("data");
	/////auto v3 = j.at("status1");

	//int foo_present = j.count("status1"); // 1 
	//int foo_present1 = j.count("status"); // 1 

	//auto v332 = RC4Decode(v2);



	VMProtectEnd();
	return result;
}

int FreeYun::GetErrorCode()
{
	return m_ErrorCode;
}

std::string FreeYun::GetErrorStr(int ErrorCode)
{
	std::string result;
	switch (ErrorCode)
	{
	case -1000: result = xorstr_(u8"接口弃用-请更新");				break;
	case -1001: result = xorstr_(u8"该服务已经停止");				break;
	case -1   :	result = xorstr_(u8"软件尚未初始化");				break;
	case -106 : result  = xorstr_(u8"表示客户端网络异常");          break;
	case -107 : result  = xorstr_(u8"表示网络数据包错误");          break;
	case 1012 : result  = xorstr_(u8"账号点数不足");				break;
	case 1011 : result  = xorstr_(u8"账号过期");					break;
	case 1028 : result  = xorstr_(u8"充值卡已被使用");				break;
	case 1045 : result  = xorstr_(u8"充值卡被封停");				break;
	case 1053 : result  = xorstr_(u8"该充值卡不允许降级充值");      break;
	case 1027 : result  = xorstr_(u8"充值卡不存在");				break;
	case 1034 : result  = xorstr_(u8"该软件卡种类为空，请后台添加");break;
	case 1036 : result  = xorstr_(u8"卡种类型不存在");				break;
	case 1042 : result  = xorstr_(u8"客户端扣点成功");				break;
	case 1024 : result  = xorstr_(u8"留言反馈成功");				break;
	case 1021 : result  = xorstr_(u8"远程JS执行失败");				break;
	case 1044 : result  = xorstr_(u8"远程代码调用次数已达上限");	break;
	case 1022 : result  = xorstr_(u8"远程JS执行成功");				break;
	case 1023 : result  = xorstr_(u8"5分钟内你已提交留言，无需再次提交");break;
	case 1046 : result  = xorstr_(u8"心跳成功");					break;
	case 1003 : result  = xorstr_(u8"软件获取初始化信息成功");      break;
	case 1020 : result  = xorstr_(u8"远程JS代码不存在");			break;
	case 1013 : result  = xorstr_(u8"软件使用人数已达多开上限");    break;
	case 1014 : result  = xorstr_(u8"登陆成功");					break;
	case 1015 : result  = xorstr_(u8"账号登陆过期");				break;
	case 1010 : result  = xorstr_(u8"机器码有误或在非绑定电脑登陆");break;
	case 1005 : result  = xorstr_(u8"机器码已经存在");				break;
	case 1031 : result  = xorstr_(u8"机器码已是绑定，无需更改");    break;
	case 1032 : result  = xorstr_(u8"软件换绑成功");				break;
	case 1026 : result  = xorstr_(u8"密码修改成功");				break;
	case 1030 : result  = xorstr_(u8"软件不允许修改机器码");        break;
	case 1038 : result  = xorstr_(u8"未开通在线收款功能");          break;
	case 1025 : result  = xorstr_(u8"修改密码原始密码错误");        break;
	case 1009 : result  = xorstr_(u8"登陆密码有误");				break;
	case 1037 : result  = xorstr_(u8"支付创建成功");				break;
	case 1047 : result  = xorstr_(u8"黑名单加入成功");				break;
	case 1035 : result  = xorstr_(u8"卡种类列表获取成功");          break;
	case 1054 : result  = xorstr_(u8"查询在线成员数成功");          break;
	case 1033 : result  = xorstr_(u8"获取更新版本信息成功");        break;
	case 1006 : result  = xorstr_(u8"账号注册成功");				break;
	case 1048 : result  = xorstr_(u8"获取用户软件权限成功");        break;
	case 1007 : result  = xorstr_(u8"软件已经关闭验证");			break;
	case 1043 : result  = xorstr_(u8"软件已经关闭注册");			break;
	case 1001 : result  = xorstr_(u8"软件不存在或密钥错误");        break;
	case 1049 : result  = xorstr_(u8"远程转发URL不存在");			break;
	case 1052 : result  = xorstr_(u8"远程转发已关闭");				break;
	case 1050 : result  = xorstr_(u8"远程转发请求异常");            break;
	case 1051 : result  = xorstr_(u8"远程转发请求成功");            break;
	case 1029 : result  = xorstr_(u8"充值成功");					break;
	case 1004 : result  = xorstr_(u8"用户名已经存在");				break;
	case 1016 : result  = xorstr_(u8"用户登陆后被删除即账号不存在");break;
	case 1017 : result  = xorstr_(u8"用户信息查询成功");            break;
	case 1008 : result  = xorstr_(u8"用户不存在");					break;
	case 1040 : result  = xorstr_(u8"用户被锁定");					break;
	case 1039 : result  = xorstr_(u8"用户状态正常");				break;
	case 1018 : result  = xorstr_(u8"远程变量不存在");				break;
	case 1019 : result  = xorstr_(u8"远程变量获取成功");			break;
	case 1041 : result  = xorstr_(u8"该软件为时间验证不支持客户端扣点");break;
	case 1002 : result  = xorstr_(u8"软件版本不存在");				break;
	default   :
			   result = xorstr_(u8"unknown information");			break;
	}

	return result;
}

std::string FreeYun::RC4Encrypt(std::string plaintext)
{
	auto util = std::make_unique<CACEUtil>();

	std::vector<BYTE>Ciphertext(plaintext.length());

	RC4_KEY s_table;

	RC4_set_key(&s_table, m_Rc4Key.length(), (unsigned char*)m_Rc4Key.c_str());					//初始化

	RC4(&s_table, plaintext.length(), (unsigned char*)plaintext.c_str(), Ciphertext.data());     //加密

	auto Rc4data = util->ByteToHex(Ciphertext.data(), Ciphertext.size());

	return Rc4data;
}

std::string FreeYun::RC4Decode(std::string Ciphertext)
{
	//先把密文转为字节
	auto util = std::make_unique<CACEUtil>();

	std::vector<BYTE>CipherByte(Ciphertext.length());

	util->HexToByte(Ciphertext.data(), CipherByte.data());

	RC4_KEY s_table;
	RC4_set_key(&s_table, m_Rc4Key.length(), (unsigned char*)m_Rc4Key.c_str());					//初始化

	std::vector<BYTE>DecodeText(Ciphertext.length());

	RC4(&s_table, CipherByte.size()/2, (unsigned char*)CipherByte.data(), DecodeText.data());     //解密


	return std::string((char*)DecodeText.data());
}

std::string FreeYun::GetStrMd5(std::string str)
{
	auto util = std::make_unique<CACEUtil>();
	unsigned char MD5result[16];

	MD5_CTX md5_ctx;
	MD5_Init(&md5_ctx);
	MD5_Update(&md5_ctx, str.c_str(), str.length());   
	MD5_Final(MD5result, &md5_ctx);  //获取MD5

	auto StrMd5 = util->ByteToHex(MD5result,16);

	return StrMd5;
}

std::string FreeYun::Post(std::string str)
{
	std::string strResponse;

	switch (m_ServerLine)
	{
	case  0:
	{
		m_HttpClient.Posts(xorstr_("https://api.freeyun.net/webgateway.html"), str, strResponse);
		if (strResponse.empty())
		{
			m_HttpClient.Posts(xorstr_("https://bgp.freeyun.net/webgateway.html"), str, strResponse);
		}
	}		
	break;
	case  1:
	{
		m_HttpClient.Posts(xorstr_("https://bgp.freeyun.net/webgateway.html"), str, strResponse);
	}		
	break;
	default:
		break;
	}
	return strResponse;
}

