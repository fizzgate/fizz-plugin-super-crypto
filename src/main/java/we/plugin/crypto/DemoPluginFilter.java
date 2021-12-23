package we.plugin.crypto;

import java.util.Map;

import javax.annotation.Resource;

import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;

import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;
import we.config.ProxyWebClientConfig;
import we.plugin.FizzPluginFilter;
import we.plugin.FizzPluginFilterChain;
import we.plugin.PluginConfig;
import we.util.ReactorUtils;

@Component(DemoPluginFilter.DEMO_PLUGIN) // 必须，且为插件 id
@Slf4j
public class DemoPluginFilter implements FizzPluginFilter {

	public static final String DEMO_PLUGIN = "demoPlugin"; // 插件 id

	@Resource(name = ProxyWebClientConfig.proxyWebClient)
	private WebClient webClient;

	@Override
	public Mono<Void> filter(ServerWebExchange exchange, Map<String, Object> config) {
		String customConfig = (String) config.get(PluginConfig.CUSTOM_CONFIG); // 获取插件级别的自定义配置信息
		System.out.println(customConfig);
		System.out.println(exchange);
		System.out.println(config);
		log.info("demo.......................");
		Mono next = FizzPluginFilterChain.next(exchange); // 执行下一个插件或后续逻辑
		return next.defaultIfEmpty(ReactorUtils.NULL).flatMap(nil -> {
			doAfterNext(); // 当 next 完成时执行一些逻辑
			return Mono.empty();
		});

	}

	public void doAfterNext() {
		System.out.println("doAfterNext============");
	}
}
