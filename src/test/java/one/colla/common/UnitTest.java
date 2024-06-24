package one.colla.common;


import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.event.RecordApplicationEvents;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@ActiveProfiles("test")
@SpringJUnitConfig
@RecordApplicationEvents
@Import(UnitTestCommonConfig.class)
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
public @interface UnitTest {
}


@TestConfiguration
class UnitTestCommonConfig {

//	@Bean
//	public TestFixtureBuilder testFixtureBuilder() {
//		return new TestFixtureBuilder();
//	}

}
