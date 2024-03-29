package com.fizzgate.plugin.crypto;

import org.springframework.context.annotation.Configuration;

import com.google.common.collect.Maps;

import com.fizzgate.config.ManualApiConfig;
import com.fizzgate.plugin.PluginConfig;
import com.fizzgate.plugin.auth.ApiConfig;
import com.fizzgate.plugin.requestbody.RequestBodyPlugin;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * 定义 DemoApiConfig 继承 ManualApiConfig，并注解为 Configuration，然后实现 setApiConfigs 方法，在方法中添加路由配置；
 * 本类仅为方便开发和测试，正式环境应该通过管理后台配置路由
 */
@Configuration
public class DemoApiConfig extends ManualApiConfig {

	@Override
	public List<ApiConfig> setApiConfigs() {

		List<ApiConfig> apiConfigs = new ArrayList<>();
//
//		ApiConfig ac = new ApiConfig(); // 一个路由配置
//
//		ac.id = 1000; // 路由 id，建议从 1000 开始
//		ac.service = "we-reward-new"; // 前端服务名
//		ac.path = "/common/testRequestGet"; // 前端路径
//		ac.type = ApiConfig.Type.REVERSE_PROXY; // 路由类型，此处为反向代理
//		ac.httpHostPorts = Collections.singletonList("http://localhost:8080"); // 被代理接口的地址
//		ac.backendPath = "/we-reward-new/common/testRequestGet"; // 被代理接口的路径
//		ac.pluginConfigs = new ArrayList<>();
//
//		// 如果你的插件需要访问请求体，则首先要把 RequestBodyPlugin.REQUEST_BODY_PLUGIN 加到
//		// ac.pluginConfigs 中，就像下面这样
//		PluginConfig pc1 = new PluginConfig();
//		pc1.plugin = RequestBodyPlugin.REQUEST_BODY_PLUGIN;
//		ac.pluginConfigs.add(pc1);
//
//		PluginConfig pc2 = new PluginConfig();
//		pc2.plugin = CryptoPluginFilter.CRYPTO_PLUGIN; // 应用 id 为 demoPlugin 的插件
//		Map<String, Object> configMap = Maps.newHashMap();
//		configMap.put("mode", 1);
//		configMap.put("secretKey", "WAYO2FvEp00Qw/CWAlI2iA==");
//		configMap.put("cryptoType", "requestHeadersCrypt");
//		configMap.put("keyType", 3);
//		configMap.put("algorithm", "AES");
//		configMap.put("jsonPath", "token");
//		pc2.config = configMap;
//		ac.pluginConfigs.add(pc2);
//
//		apiConfigs.add(ac);
//
//		log.info("set api configs end");
		return apiConfigs; // 返回路由配置
	}
}
