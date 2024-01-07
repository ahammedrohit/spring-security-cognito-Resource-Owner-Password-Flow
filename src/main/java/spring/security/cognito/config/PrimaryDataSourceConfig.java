package spring.security.cognito.config;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import org.apache.ibatis.session.SqlSessionFactory;
import org.mybatis.spring.SqlSessionFactoryBean;
import org.mybatis.spring.annotation.MapperScan;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.transaction.PlatformTransactionManager;

import javax.sql.DataSource;

@Configuration
@MapperScan(basePackages = {"spring.security.cognito.infrastructure"},
        sqlSessionFactoryRef = "primarySqlSessionFactory")
public class PrimaryDataSourceConfig {

  /**
   * DataSource のBeanを生成して返します.
   *
   * @param hikariConfig HikariDataSourceの設定
   * @return DataSource
   */
  @Primary
  @Bean(name = {"primaryDataSource"})
  public DataSource dataSource(
          @Qualifier("primaryHikariConfig") HikariConfig hikariConfig) {
    return new HikariDataSource(hikariConfig);
  }

  @Bean(name = {"primaryHikariConfig"})
  @Primary
  @ConfigurationProperties(prefix = "spring.datasource.primary.hikari")
  public HikariConfig hikariConfig() {
    return new HikariConfig();
  }

  /**
   * Create transaction manager.
   */
  @Primary
  @Bean(name = {"primaryTxManager"})
  public PlatformTransactionManager txManager(
          @Qualifier("primaryDataSource") DataSource dataSource) {

    DataSourceTransactionManager transactionManager = new DataSourceTransactionManager(dataSource);
    transactionManager.setRollbackOnCommitFailure(true);
    return transactionManager;
  }

  /**
   * Create sql session factory.
   */
  @Primary
  @Bean(name = {"primarySqlSessionFactory"})
  public SqlSessionFactory sqlSessionFactory(
          @Qualifier("primaryDataSource") DataSource dataSource) throws Exception {

    SqlSessionFactoryBean sqlSessionFactoryBean = new SqlSessionFactoryBean();
    sqlSessionFactoryBean.setDataSource(dataSource);
    sqlSessionFactoryBean.setConfigLocation(new ClassPathResource("/mybatis-config.xml"));
    return (SqlSessionFactory) sqlSessionFactoryBean.getObject();
  }
}
