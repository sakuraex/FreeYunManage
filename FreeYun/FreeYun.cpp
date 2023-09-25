#include "FreeYun.h"
#include <ctime>
#include "VMProtectSDK.h"
#include "openssl/rc4.h"
#include "openssl/md5.h"
#include "xorstr.hpp"


FreeYun::FreeYun()
{
	m_pInstance = this;
}

FreeYun* FreeYun::GetpInstance()
{
	if (m_pInstance  == nullptr)
	{
		m_pInstance = new FreeYun();
	}
	return m_pInstance;
}

std::tuple<bool, std::string, nlohmann::json> FreeYun::CloudInit(PTAG_ANTI_FREEYUN_INIT_INFO pInfo)
{
	VMProtectBegin(__FUNCTION__);

	m_Version    = pInfo->Version;
	m_SecretKey  = pInfo->SecretKey;
	m_Rc4Key     = pInfo->Rc4Key;
	m_SaltKey    = pInfo->SaltKey;
	m_AppId      = pInfo->AppId;
	m_MachineID  = pInfo->MachineID;
	m_ServerLine = pInfo->ServerLine;

	if (pInfo->Proxy.IP.empty() == false)
	{
		m_HttpClient.SetProxy(pInfo->Proxy.IP, pInfo->Proxy.Port, pInfo->Proxy.User, pInfo->Proxy.PassWord);
	}

	std::tuple<bool, std::string, nlohmann::json>  result = std::make_tuple(false,"","");

	
	// 获取时间戳
	auto csTime = GetTimeStampStr();

	// 要发送的数据
	FreeYun_json SendJsonData=
	{
		{ xorstr_("version" ) , m_Version},
		{ xorstr_("timestamp"), csTime },
		{ xorstr_("macCode") , m_MachineID},
		{ xorstr_("secretKey"), m_SecretKey}
	};

	DetectInfo(GetPostPack(SendJsonData.dump(), std::to_string(1), csTime),result,1003);

	VMProtectEnd();
	return result;
}

std::tuple<bool, std::string, nlohmann::json> FreeYun::CloudReg(PTAG_ANTI_FREEYUN_REG pInfo)
{
	VMProtectBegin(__FUNCTION__);
	std::tuple<bool, std::string, nlohmann::json>  result = std::make_tuple(false, "", "");
	
	// 获取时间戳
	auto csTime = GetTimeStampStr();

	// 要发送的数据
	FreeYun_json SendJsonData =
	{
		{ xorstr_("account")     , pInfo->Account},
		{ xorstr_("password")    , pInfo->Password },
		{ xorstr_("macCode")     , m_MachineID},
		{ xorstr_("timestamp")   , csTime},
		{ xorstr_("secretKey")   , m_SecretKey},
		{ xorstr_("qq")          , pInfo->QQ},
		{ xorstr_("email")       , pInfo->Email},
		{ xorstr_("mobile")      , pInfo->Mobile},
		{ xorstr_("invitingCode"), pInfo->InvitingCode},
		{ xorstr_("agentCode")   , pInfo->AgentCode},
	};
	
	DetectInfo(GetPostPack(SendJsonData.dump(), std::to_string(2), csTime), result, 1006);

	VMProtectEnd();
	return result;
}

std::tuple<bool, std::string, nlohmann::json> FreeYun::CloudLogin(std::string Account, std::string Password, std::string md5)
{
	VMProtectBegin(__FUNCTION__);
	std::tuple<bool, std::string, nlohmann::json>  result = std::make_tuple(false, "", "");
	
	// 获取时间戳
	auto csTime = GetTimeStampStr();

	// 要发送的数据
	FreeYun_json SendJsonData =
	{
		{ xorstr_("account")     , Account},
		{ xorstr_("password")    , Password },
		{ xorstr_("macCode")     , m_MachineID},
		{ xorstr_("timestamp")   , csTime},
		{ xorstr_("secretKey")   , m_SecretKey},
		{ xorstr_("version")     , m_Version},
		{ xorstr_("md5")         , md5},
	};

	DetectInfo(GetPostPack(SendJsonData.dump(), std::to_string(3), csTime), result, 1014);

	if (std::get<0>(result) && std::get<2>(result).contains(xorstr_("token")))
	{
		m_Token = std::get<2>(result)[xorstr_("token")].get<std::string>();
	}


	VMProtectEnd();
	return result;
}

std::tuple<bool, std::string, nlohmann::json> FreeYun::CloudPay(std::string Account, std::string cardNo)
{
	VMProtectBegin(__FUNCTION__);
	std::tuple<bool, std::string, nlohmann::json>  result = std::make_tuple(false, "", "");
	
	// 获取时间戳
	auto csTime = GetTimeStampStr();

	// 要发送的数据
	FreeYun_json SendJsonData =
	{
		{ xorstr_("account")     , Account},
		{ xorstr_("cardNo")      , cardNo },
		{ xorstr_("macCode")     , m_MachineID},
		{ xorstr_("timestamp")   , csTime},
		{ xorstr_("secretKey")   , m_SecretKey},

	};

	DetectInfo(GetPostPack(SendJsonData.dump(), std::to_string(4), csTime), result, 1029);

	VMProtectEnd();
	return result;
}

std::tuple<bool, std::string, nlohmann::json> FreeYun::CloudQueryUserInfo(std::string Account)
{
	VMProtectBegin(__FUNCTION__);
	std::tuple<bool, std::string, nlohmann::json>  result = std::make_tuple(false, "", "");
	
	// 获取时间戳
	auto csTime = GetTimeStampStr();

	// 要发送的数据
	FreeYun_json SendJsonData =
	{
		{ xorstr_("account")     , Account},
		{ xorstr_("token")      ,  m_Token },
		{ xorstr_("macCode")     , m_MachineID},
		{ xorstr_("timestamp")   , csTime},
		{ xorstr_("secretKey")   , m_SecretKey},

	};

	DetectInfo(GetPostPack(SendJsonData.dump(), std::to_string(6), csTime), result, 1017);

	VMProtectEnd();
	return result;
}

std::tuple<bool, std::string, nlohmann::json> FreeYun::CloudBlackLst(std::string Account, ULONG Type /*= 2*/)
{
	VMProtectBegin(__FUNCTION__);
	std::tuple<bool, std::string, nlohmann::json>  result = std::make_tuple(false, "", "");

	// 获取时间戳
	auto csTime = GetTimeStampStr();

	// 要发送的数据
	FreeYun_json SendJsonData =
	{
		{ xorstr_("blackType")     , Type},
		{ xorstr_("account")       , Account },
		{ xorstr_("macCode")       , m_MachineID},
		{ xorstr_("timestamp")     , csTime},
		{ xorstr_("secretKey")     , m_SecretKey},

	};

	DetectInfo(GetPostPack(SendJsonData.dump(), std::to_string(20), csTime), result, 1048);

	VMProtectEnd();
	return result;
}

std::tuple<bool, std::string, nlohmann::json> FreeYun::CloudChangePassword(std::string Account, std::string oldPwd, std::string newPwd)
{
	VMProtectBegin(__FUNCTION__);
	std::tuple<bool, std::string, nlohmann::json>  result = std::make_tuple(false, "", "");
	
	// 获取时间戳
	auto csTime =GetTimeStampStr();

	// 要发送的数据
	FreeYun_json SendJsonData =
	{
		{ xorstr_("oldPwd")        , oldPwd},
		{ xorstr_("newPwd")        , newPwd},
		{ xorstr_("account")       , Account },
		{ xorstr_("macCode")       , m_MachineID},
		{ xorstr_("timestamp")     , csTime},
		{ xorstr_("secretKey")     , m_SecretKey},

	};

	DetectInfo(GetPostPack(SendJsonData.dump(), std::to_string(13), csTime), result, 1026);

	VMProtectEnd();
	return result;
}

std::tuple<bool, std::string, nlohmann::json> FreeYun::CloudExit(std::string Account)
{
	VMProtectBegin(__FUNCTION__);
	std::tuple<bool, std::string, nlohmann::json>  result = std::make_tuple(false, "", "");
	
	// 获取时间戳
	auto csTime =GetTimeStampStr();

	// 要发送的数据
	FreeYun_json SendJsonData =
	{
		{ xorstr_("token")         , m_Token},
		{ xorstr_("account")       , Account },
		{ xorstr_("macCode")       , m_MachineID},
		{ xorstr_("timestamp")     , csTime},
		{ xorstr_("secretKey")     , m_SecretKey},

	};

	DetectInfo(GetPostPack(SendJsonData.dump(), std::to_string(14), csTime), result, 1);

	VMProtectEnd();
	return result;
}

std::tuple<bool, std::string, nlohmann::json> FreeYun::CloudGetVersionInfo()
{
	VMProtectBegin(__FUNCTION__);
	std::tuple<bool, std::string, nlohmann::json>  result = std::make_tuple(false, "", "");
	
	// 获取时间戳
	auto csTime = GetTimeStampStr();

	// 要发送的数据
	FreeYun_json SendJsonData =
	{
		{ xorstr_("version")       , m_Version},
		{ xorstr_("macCode")       , m_MachineID},
		{ xorstr_("timestamp")     , csTime},
		{ xorstr_("secretKey")     , m_SecretKey},

	};

	DetectInfo(GetPostPack(SendJsonData.dump(), std::to_string(15), csTime), result, 1033);

	VMProtectEnd();
	return result;

}


std::tuple<bool, std::string, nlohmann::json> FreeYun::CloudGetUserStatus(std::string Account)
{
	VMProtectBegin(__FUNCTION__);
	std::tuple<bool, std::string, nlohmann::json>  result = std::make_tuple(false, "", "");

	// 获取时间戳
	auto csTime = GetTimeStampStr();

	// 要发送的数据
	FreeYun_json SendJsonData =
	{
		{ xorstr_("token")         , m_Token},
		{ xorstr_("account")       , Account },
		{ xorstr_("macCode")       , m_MachineID},
		{ xorstr_("timestamp")     , csTime},
		{ xorstr_("secretKey")     , m_SecretKey},

	};

	DetectInfo(GetPostPack(SendJsonData.dump(), std::to_string(17), csTime), result, 1039);

	VMProtectEnd();
	return result;

}

std::tuple<bool, std::string, nlohmann::json> FreeYun::CloudUserSubPoint(std::string Account, int Value)
{
	VMProtectBegin(__FUNCTION__);
	std::tuple<bool, std::string, nlohmann::json>  result = std::make_tuple(false, "", "");
	
	// 获取时间戳
	auto csTime = GetTimeStampStr();

	// 要发送的数据
	FreeYun_json SendJsonData =
	{
		{ xorstr_("subValue")      , Value},
		{ xorstr_("token")         , m_Token},
		{ xorstr_("account")       , Account },
		{ xorstr_("macCode")       , m_MachineID},
		{ xorstr_("timestamp")     , csTime},
		{ xorstr_("secretKey")     , m_SecretKey},

	};

	DetectInfo(GetPostPack(SendJsonData.dump(), std::to_string(18), csTime), result, 1042);

	VMProtectEnd();
	return result;
}
std::tuple<bool, std::string, nlohmann::json> FreeYun::CloudGetPayCardList()
{
	VMProtectBegin(__FUNCTION__);
	std::tuple<bool, std::string, nlohmann::json>  result = std::make_tuple(false, "", "");

	// 获取时间戳
	auto csTime = GetTimeStampStr();

	// 要发送的数据
	FreeYun_json SendJsonData =
	{
		{ xorstr_("macCode")       , m_MachineID},
		{ xorstr_("timestamp")     , csTime},
		{ xorstr_("secretKey")     , m_SecretKey},

	};

	DetectInfo(GetPostPack(SendJsonData.dump(), std::to_string(16), csTime), result, 1035);

	VMProtectEnd();
	return result;
}
std::tuple<bool, std::string, nlohmann::json> FreeYun::CloudCardLogin(std::string Card, std::string md5)
{
	VMProtectBegin(__FUNCTION__);
	std::tuple<bool, std::string, nlohmann::json>  result = std::make_tuple(false, "", "");
	
	// 获取时间戳
	auto csTime = GetTimeStampStr();

	// 要发送的数据
	FreeYun_json SendJsonData =
	{
		{ xorstr_("account")     , Card},
		{ xorstr_("macCode")     , m_MachineID},
		{ xorstr_("timestamp")   , csTime},
		{ xorstr_("secretKey")   , m_SecretKey},
		{ xorstr_("version")     , m_Version},
		{ xorstr_("md5")         , md5},
	};

	DetectInfo(GetPostPack(SendJsonData.dump(), std::to_string(19), csTime), result, 1014);

	if (std::get<0>(result) && std::get<2>(result).contains(xorstr_("token")))
	{
		m_Token = std::get<2>(result)[xorstr_("token")].get<std::string>();
	}


	VMProtectEnd();
	return result;
}



std::tuple<bool, std::string, nlohmann::json> FreeYun::CloudExecTelnetCode(std::string Account, std::string lableName, std::string funcName, std::string params)
{
	VMProtectBegin(__FUNCTION__);
	std::tuple<bool, std::string, nlohmann::json>  result = std::make_tuple(false, "", "");
	
	// 获取时间戳
	auto csTime = GetTimeStampStr();

	// 要发送的数据
	FreeYun_json SendJsonData =
	{
		{ xorstr_("account")     , Account},
		{ xorstr_("macCode")     , m_MachineID},
		{ xorstr_("lableName")   ,lableName},
		{ xorstr_("token")		 , m_Token},	
		{ xorstr_("timestamp")	 , csTime},
		{ xorstr_("secretKey")   , m_SecretKey},
		{ xorstr_("version")     , m_Version},
		{ xorstr_("funcName")      , funcName},
		{ xorstr_("params")      , params},
	};

	DetectInfo(GetPostPack(SendJsonData.dump(), std::to_string(7), csTime), result, 1022);


	VMProtectEnd();
	return result;
}

std::tuple<bool, std::string, nlohmann::json> FreeYun::CloudGetTeletVar(std::string Account, std::string keyName)
{
	VMProtectBegin(__FUNCTION__);
	std::tuple<bool, std::string, nlohmann::json>  result = std::make_tuple(false, "", "");
	
	// 获取时间戳
	auto csTime = GetTimeStampStr();

	// 要发送的数据
	FreeYun_json SendJsonData =
	{
		{ xorstr_("account")     , Account},
		{ xorstr_("macCode")     , m_MachineID},	
		{ xorstr_("token")		 , m_Token},
		{ xorstr_("timestamp")	 , csTime},
		{ xorstr_("secretKey")   , m_SecretKey},
		{ xorstr_("version")     , m_Version},
		{ xorstr_("keyName")      , keyName},
	};

	DetectInfo(GetPostPack(SendJsonData.dump(), std::to_string(8), csTime), result, 1019);


	VMProtectEnd();
	return result;
}

std::tuple<bool, std::string, nlohmann::json> FreeYun::CloudHeartBeat(std::string Account)
{
	VMProtectBegin(__FUNCTION__);
	std::tuple<bool, std::string, nlohmann::json>  result = std::make_tuple(false, "", "");

	// 获取时间戳
	auto csTime = GetTimeStampStr();

	// 要发送的数据
	FreeYun_json SendJsonData =
	{
		{ xorstr_("account")     , Account},
		{ xorstr_("macCode")     , m_MachineID},
		{ xorstr_("token")		 , m_Token},
		{ xorstr_("timestamp")	 , csTime},
		{ xorstr_("secretKey")   , m_SecretKey},
	};

	DetectInfo(GetPostPack(SendJsonData.dump(), std::to_string(9), csTime), result, 1046);

	VMProtectEnd();
	return result;
}

std::tuple<bool, std::string, nlohmann::json> FreeYun::CloudChangeMachine(std::string Account, std::string PassWord)
{
	VMProtectBegin(__FUNCTION__);
	std::tuple<bool, std::string, nlohmann::json>  result = std::make_tuple(false, "", "");

	// 获取时间戳
	auto csTime = GetTimeStampStr();

	// 要发送的数据
	FreeYun_json SendJsonData =
	{
		{ xorstr_("account")     , Account},
		{ xorstr_("password")     , PassWord},
		//如果密码为空 则为 单码模式 2  否则就是 账号密码模式 1
		{ xorstr_("userType")     , PassWord.empty() ? 2 : 1},		
		{ xorstr_("macCode")     , m_MachineID},
		{ xorstr_("timestamp")	 , csTime},
		{ xorstr_("secretKey")   , m_SecretKey},
	};

	DetectInfo(GetPostPack(SendJsonData.dump(), std::to_string(10), csTime), result, 1032);

	VMProtectEnd();
	return result;
}

std::tuple<bool, std::string, nlohmann::json> FreeYun::CloudFeedback(std::string Context, std::string links)
{
	VMProtectBegin(__FUNCTION__);
	std::tuple<bool, std::string, nlohmann::json>  result = std::make_tuple(false, "", "");
	
	// 获取时间戳
	auto csTime =GetTimeStampStr();

	// 要发送的数据
	FreeYun_json SendJsonData =
	{
		{ xorstr_("context")     , Context},
		{ xorstr_("version")     , m_Version},
		{ xorstr_("links")      , links},
		{ xorstr_("macCode")     , m_MachineID},
		{ xorstr_("timestamp")	 , csTime},
		{ xorstr_("secretKey")   , m_SecretKey},
	};

	DetectInfo(GetPostPack(SendJsonData.dump(), std::to_string(11), csTime), result, 1024);

	VMProtectEnd();
	return result;
}

std::tuple<bool, std::string, nlohmann::json> FreeYun::CloudUpLoadClientExceptionInfo(std::string ExceptionTag, std::string Context, std::string operaSystem)
{
	VMProtectBegin(__FUNCTION__);
	std::tuple<bool, std::string, nlohmann::json>  result = std::make_tuple(false, "", "");
	
	// 获取时间戳
	auto csTime = GetTimeStampStr();

	// 要发送的数据
	FreeYun_json SendJsonData =
	{
		{ xorstr_("operaSystem")     , operaSystem},
		{ xorstr_("context")     , Context},
		{ xorstr_("version")     , m_Version},
		{ xorstr_("bugTag")      , ExceptionTag},
		{ xorstr_("macCode")     , m_MachineID},
		{ xorstr_("timestamp")	 , csTime},
		{ xorstr_("secretKey")   , m_SecretKey},
	};

	DetectInfo(GetPostPack(SendJsonData.dump(), std::to_string(12), csTime), result, 1024);

	VMProtectEnd();
	return result;
}

std::tuple<bool, std::string, nlohmann::json> FreeYun::CloudGetUserPermission(std::string Account)
{
	VMProtectBegin(__FUNCTION__);
	std::tuple<bool, std::string, nlohmann::json>  result = std::make_tuple(false, "", "");
	
	// 获取时间戳
	auto csTime = GetTimeStampStr();

	// 要发送的数据
	FreeYun_json SendJsonData =
	{
		{ xorstr_("account")     , Account},
		{ xorstr_("token")     , m_Token},

		{ xorstr_("macCode")     , m_MachineID},
		{ xorstr_("timestamp")	 , csTime},
		{ xorstr_("secretKey")   , m_SecretKey},
	};

	DetectInfo(GetPostPack(SendJsonData.dump(), std::to_string(21), csTime), result, 1048);

	VMProtectEnd();
	return result;
}

std::tuple<bool, std::string, nlohmann::json> FreeYun::CloudRemoteAlgRelay(std::string Account, std::string remoteId, std::string params)
{
	VMProtectBegin(__FUNCTION__);
	std::tuple<bool, std::string, nlohmann::json>  result = std::make_tuple(false, "", "");
	
	// 获取时间戳
	auto csTime = GetTimeStampStr();

	// 要发送的数据
	FreeYun_json SendJsonData =
	{
		{ xorstr_("account")      , Account},
		{ xorstr_("token")        , m_Token},
		{ xorstr_("remoteId")     , remoteId},
		{ xorstr_("params")       , params},
		{ xorstr_("macCode")      , m_MachineID},
		{ xorstr_("timestamp")	  , csTime},
		{ xorstr_("secretKey")    , m_SecretKey},
	};

	DetectInfo(GetPostPack(SendJsonData.dump(), std::to_string(22), csTime), result, 1051);

	VMProtectEnd();
	return result;
}

std::tuple<bool, std::string, nlohmann::json> FreeYun::CloudUsersOnlineCount()
{
	VMProtectBegin(__FUNCTION__);
	std::tuple<bool, std::string, nlohmann::json>  result = std::make_tuple(false, "", "");
	
	// 获取时间戳
	auto csTime = GetTimeStampStr();

	// 要发送的数据
	FreeYun_json SendJsonData =
	{
		
		{ xorstr_("token")        , m_Token},
		{ xorstr_("macCode")      , m_MachineID},
		{ xorstr_("timestamp")	  , csTime},
		{ xorstr_("secretKey")    , m_SecretKey},
	};

	DetectInfo(GetPostPack(SendJsonData.dump(), std::to_string(23), csTime), result, 1054);

	VMProtectEnd();
	return result;
}

std::tuple<bool, std::string, nlohmann::json> FreeYun::CloudUserUnBind(std::string Account, std::string PassWord /*= ""*/)
{
	VMProtectBegin(__FUNCTION__);
	std::tuple<bool, std::string, nlohmann::json>  result = std::make_tuple(false, "", "");
	
	// 获取时间戳
	auto csTime = GetTimeStampStr();

	// 要发送的数据
	FreeYun_json SendJsonData =
	{

		{ xorstr_("account")        , Account},
		{ xorstr_("password")       ,PassWord},
		{ xorstr_("userType")     , PassWord.empty() ? 2 : 1},
		{ xorstr_("macCode")      , m_MachineID},
		{ xorstr_("timestamp")	  , csTime},
		{ xorstr_("secretKey")    , m_SecretKey},
	};

	DetectInfo(GetPostPack(SendJsonData.dump(), std::to_string(24), csTime), result, 1032);

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
	//自定义的返回码
	case -9000: result = xorstr_(u8"网络连接失败,请重试!");			break;
	case -9001: result = xorstr_("Htpp:Status Error:{} Status:{}");	break;
	case -9002: result = xorstr_(u8"状态获取失败");					break;
	case -9003: result = xorstr_(u8"未找到返回码 Code");			break;
	// 验证的返回码 
	case -1000: result = xorstr_(u8"接口弃用-请更新");				break;
	case -1001: result = xorstr_(u8"该服务已经停止");				break;
	case -1   :	result = xorstr_(u8"软件尚未初始化");				break;
	case -106 : result  = xorstr_(u8"表示客户端网络异常");          break;
	case -107 : result  = xorstr_(u8"表示网络数据包错误");          break;
	case -108: result = xorstr_(u8"加密的参数校验有误");				break;
	case -109: result = xorstr_(u8"服务器异常或繁忙、可重新获取一次");  break;
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

std::string FreeYun::SetErrorCode(int ErCode)
{
	return GetErrorStr(m_ErrorCode = ErCode);
}

std::string FreeYun::RC4Encrypt(std::string plaintext)
{
	

	std::vector<BYTE>Ciphertext(plaintext.length());

	RC4_KEY s_table;

	RC4_set_key(&s_table, m_Rc4Key.length(), (unsigned char*)m_Rc4Key.c_str());					//初始化

	RC4(&s_table, plaintext.length(), (unsigned char*)plaintext.c_str(), Ciphertext.data());     //加密

	auto Rc4data = ByteToHex(Ciphertext.data(), Ciphertext.size());

	return Rc4data;
}

std::string FreeYun::RC4Decode(std::string Ciphertext)
{
	
	std::vector<BYTE>CipherByte(Ciphertext.length());

	HexToByte(Ciphertext.data(), CipherByte.data());

	RC4_KEY s_table;
	RC4_set_key(&s_table, m_Rc4Key.length(), (unsigned char*)m_Rc4Key.c_str());					//初始化

	std::vector<BYTE>DecodeText(Ciphertext.length());

	RC4(&s_table, CipherByte.size()/2, (unsigned char*)CipherByte.data(), DecodeText.data());     //解密


	return std::string((char*)DecodeText.data());
}

std::string FreeYun::GetStrMd5(std::string str)
{
	
	unsigned char MD5result[16];

	MD5_CTX md5_ctx;
	MD5_Init(&md5_ctx);
	MD5_Update(&md5_ctx, str.c_str(), str.length());   
	MD5_Final(MD5result, &md5_ctx);  //获取MD5

	auto StrMd5 = ByteToHex(MD5result,16);

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

			if(!strResponse.empty())
			{
				// 如果第一条线路崩溃.BGP线路可行.将自动切换第二条线路
				m_ServerLine = 1;
			}

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

std::string FreeYun::GetPostPack(std::string data, std::string wtype, std::string csTime)
{
	//RC4加密发送的数据
	auto RC4SendData = RC4Encrypt(data);
	//@ 操作类型
	//@ 时间戳
	//@ 签名盐
	//@ appid
	//@ RC4加密的data

	char szText[4096] = { 0 };

	sprintf(szText, xorstr_("%s%s%s%s%s"), wtype.data(), csTime.data(), m_SaltKey.data(), m_AppId.data(), RC4SendData.data());

	//std::string csSendDataToMd5 = fmt::format(xorstr_("{0}{1}{2}{3}{4}"), wtype, csTime, m_SaltKey, m_AppId, RC4SendData);
	
	char szSendText[4096] = { 0 };

	sprintf(szSendText, xorstr_("version=%s&appid=%s&wtype=%s&timestamp=%s&data=%s&sign=%s"), m_Version.data(), m_AppId.data(), wtype.data(), csTime.data(),  RC4SendData.data(), GetStrMd5(szText).data());

	//@ 发送的字符串
	//std::string SendStr = fmt::format(xorstr_("version={}&appid={}&wtype={}&timestamp={}&data={}&sign={}"), m_Version, m_AppId, wtype, csTime, RC4SendData, GetStrMd5(szText));

	return  this->Post(szSendText);
}

std::tuple<bool, std::string, nlohmann::json> FreeYun::DetectInfo(std::string data, std::tuple<bool, std::string, nlohmann::json>& Info, int nCode)
{
	if (data.empty())
	{
		std::get<1>(Info) = SetErrorCode(-9000);
		return Info;
	}
	auto j = nlohmann::json::parse(data);
	if (int k = j.count(xorstr_("status")); k >= 1)
	{
		auto Status = j[xorstr_("status")].get<int>();

		if (Status != 0)
		{
			//std::get<1>(Info) = fmt::format(SetErrorCode(-9001), j[xorstr_("msg")].get<std::string>(), Status);  Htpp:Status Error
			std::get<1>(Info) = SetErrorCode(-9001);
			return Info;
		}
		auto data = nlohmann::json::parse(RC4Decode(j[xorstr_("data")].get<std::string>()));

		if (data.contains(xorstr_("code")))
		{
			auto Code = data[xorstr_("code")].get<int>();

			if (Code == nCode)
			{
				std::get<0>(Info) = true;
				std::get<2>(Info) = data;
				return Info;
			}

			std::get<1>(Info) = SetErrorCode(Code);
			return Info;
		}
		//未找到返回码
		std::get<1>(Info) = SetErrorCode(-9003);
		return Info;
	}

	//status 获取失败
	std::get<1>(Info) = SetErrorCode(-9002);
	return Info;
}

__int64 FreeYun::GetTimeStamp()
{
	SYSTEMTIME tmSys;

	GetLocalTime(&tmSys);

	time_t curtime;

	time(&curtime);

	__int64 tmDst = __int64(curtime) * 1000 + tmSys.wMilliseconds;

	//_i64toa(tmDst, (char*)data.c_str(), 10);
	return tmDst;
}

ULONG FreeYun::GetUnixTimeStamp()
{
	time_t curtime;

	time(&curtime);

	return curtime;
}

std::string FreeYun::GetTimeStampStr()
{
	return std::to_string(GetTimeStamp());
}

std::string FreeYun::ByteToHex(PBYTE vByte, int vLen)
{
	std::vector<BYTE> Buffer(vLen * 2 + 1);
	int tmp2;
	for (int i = 0; i < vLen; i++)
	{
		tmp2 = (int)(vByte[i]) / 16;
		Buffer[i * 2] = (char)(tmp2 + ((tmp2 > 9) ? 'A' - 10 : '0'));
		tmp2 = (int)(vByte[i]) % 16;
		Buffer[i * 2 + 1] = (char)(tmp2 + ((tmp2 > 9) ? 'A' - 10 : '0'));
	}
	Buffer[vLen * 2] = '\0';

	return std::string((char*)Buffer.data());
}

PBYTE FreeYun::HexToByte(std::string Hex, PBYTE SrcBuffer)
{

	int iLen = Hex.length();

	if (iLen <= 0 || 0 != iLen % 2)
		return nullptr;

	unsigned char* pbBuf = SrcBuffer;  // 数据缓冲区

	int tmp1, tmp2;
	for (int i = 0; i < iLen / 2; i++)
	{
		if ((Hex[i * 2] >= 'A') && (Hex[i * 2] <= 'F'))
		{
			tmp1 = (int)Hex[i * 2] - (((int)Hex[i * 2] >= 'A') ? 'A' - 10 : '0');
		}
		else if ((Hex[i * 2] >= 'a') && (Hex[i * 2] <= 'f'))
		{
			tmp1 = (int)Hex[i * 2] - (((int)Hex[i * 2] >= 'a') ? 'a' - 10 : '0');
		}
		else
		{
			tmp1 = (int)Hex[i * 2] - '0';
		}

		if (tmp1 >= 16)
			return nullptr;

		if ((Hex[i * 2 + 1] >= 'A') && (Hex[i * 2 + 1] <= 'F'))
		{

			tmp2 = (int)Hex[i * 2 + 1] - (((int)Hex[i * 2 + 1] >= 'A') ? 'A' - 10 : '0');
		}
		else if ((Hex[i * 2 + 1] >= 'a') && (Hex[i * 2 + 1] <= 'f'))
		{
			tmp2 = (int)Hex[i * 2 + 1] - (((int)Hex[i * 2 + 1] >= 'a') ? 'a' - 10 : '0');
		}
		else
		{
			tmp2 = (int)Hex[i * 2 + 1] - '0';
		}

		if (tmp2 >= 16)
			return nullptr;

		pbBuf[i] = (tmp1 * 16 + tmp2);
	}

	return pbBuf;
}