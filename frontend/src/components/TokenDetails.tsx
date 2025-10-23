import React from 'react';
import { Card, Table, Typography, Tag, Space, Descriptions, Tabs } from 'antd';
import { TokenEvaluationResult, TokenType } from '@/types/token';
import { getTokenExpirationInfo } from '@/utils/tokenAdapter';

const { Text } = Typography;

// 将信任向量评分转换为状态标签
const getTrustLevelTag = (value: number) => {
  if (value === undefined) return null;
  
  // AR4SI 语义：数值并非“越大越可信”，而是编码区间
  // 0–32: 可信，33–96: 警告，97–127: 禁用；负数：未知/未定义
  if (value >= 97) {
    return <Tag color="red">禁用 ({value})</Tag>;
  } else if (value >= 33) {
    return <Tag color="orange">警告 ({value})</Tag>;
  } else if (value >= 0) {
    return <Tag color="green">可信 ({value})</Tag>;
  } else {
    return <Tag>未知 ({value})</Tag>;
  }
};

interface TokenDetailsProps {
  evaluationResult: TokenEvaluationResult;
}



// 渲染Simple Token的详细信息
const SimpleTokenDetails: React.FC<{ result: TokenEvaluationResult }> = ({ result }) => {
  const claims = result.rawClaims;
  
  return (
    <>
      <Card style={{ marginBottom: 16 }}>
        <Descriptions title="Simple Token 详情" bordered>
          <Descriptions.Item label="验证结果">
            <Tag color={result.isValid ? 'green' : 'red'}>
              {result.isValid ? '通过' : '失败'}
            </Tag>
          </Descriptions.Item>
          <Descriptions.Item label="过期时间">
            {getTokenExpirationInfo(result)}
          </Descriptions.Item>
          <Descriptions.Item label="TEE类型">
            {claims.tee}
          </Descriptions.Item>
          <Descriptions.Item label="发行者">
            {claims.iss}
          </Descriptions.Item>
          <Descriptions.Item label="JWK算法">
            {claims.jwk.alg}
          </Descriptions.Item>
        </Descriptions>
      </Card>

      <Card
        title={
          <Space>
            <span>验证结果</span>
            <Tag color={result.isValid ? 'green' : 'red'}>
              {result.isValid ? '通过' : '失败'}
            </Tag>
          </Space>
        }
        extra={
          <Text type="secondary">
            策略: {claims['evaluation-reports'][0]['policy-id']}
          </Text>
        }
      >
        <Tabs
          defaultActiveKey="evaluation"
          items={[
            {
              key: 'evaluation',
              label: '评估结果',
              children: (
                <Descriptions column={1} bordered size="small">
                  {claims['evaluation-reports']?.[0]?.['policy-hash'] && (
                    <Descriptions.Item label="策略哈希">
                      <Text style={{ wordBreak: 'break-all' }}>
                        {claims['evaluation-reports'][0]['policy-hash']}
                      </Text>
                    </Descriptions.Item>
                  )}
                  {claims.customized_claims && Object.keys(claims.customized_claims).length > 0 && (
                    <Descriptions.Item label="自定义声明">
                      <div style={{ background: '#f5f5f5', padding: 16, borderRadius: 4 }}>
                        <pre style={{ margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
                          {JSON.stringify(claims.customized_claims, null, 2)}
                        </pre>
                      </div>
                    </Descriptions.Item>
                  )}
                </Descriptions>
              )
            },
            ...(claims['tcb-status'] && Object.keys(claims['tcb-status']).length > 0 ? [{
              key: 'tcb_status',
              label: 'TCB状态',
              children: (
                <div style={{ background: '#f5f5f5', padding: 16, borderRadius: 4 }}>
                  <pre style={{ margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
                    {JSON.stringify(claims['tcb-status'], null, 2)}
                  </pre>
                </div>
              )
            }] : []),
            ...(claims['reference-data'] && Object.keys(claims['reference-data']).length > 0 ? [{
              key: 'reference_data',
              label: '参考数据',
              children: (
                <div style={{ background: '#f5f5f5', padding: 16, borderRadius: 4 }}>
                  <pre style={{ margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
                    {JSON.stringify(claims['reference-data'], null, 2)}
                  </pre>
                </div>
              )
            }] : [])
          ]}
        />
      </Card>
    </>
  );
};

// 渲染EAR Token的详细信息
const EarTokenDetails: React.FC<{ result: TokenEvaluationResult }> = ({ result }) => {
  const claims = result.rawClaims;


  const columns = [
    {
      title: '维度',
      dataIndex: 'dimension',
      key: 'dimension',
    },
    {
      title: '信任级别',
      dataIndex: 'value',
      key: 'value',
      render: (value: number) => getTrustLevelTag(value),
    },
  ];

  const renderTrustVector = (submodKey: string, submodData: any) => {
    const vector = submodData['ear.trustworthiness-vector'];
    const data = Object.entries(vector).map(([key, value]) => ({
      key,
      dimension: key,
      value,
    }));

    return (
      <Card
        key={submodKey}
        title={
          <Space>
            <span>设备 {submodKey}</span>
            <Tag color={
              submodData['ear.status'] === 'valid' ? 'green' :
              submodData['ear.status'] === 'warning' ? 'orange' :
              'red'
            }>
              {submodData['ear.status']}
            </Tag>
          </Space>
        }
        style={{ marginBottom: 16 }}
        extra={
          <Text type="secondary">
            策略: {submodData['ear.appraisal-policy-id']}
          </Text>
        }
      >
        <Tabs
          defaultActiveKey="trust_vector"
          items={[
            {
              key: 'trust_vector',
              label: '信任向量',
              children: (
                <Table
                  columns={columns}
                  dataSource={data}
                  pagination={false}
                  size="small"
                />
              )
            },
            {
              key: 'evidence',
              label: '证据详情',
              children: (
                <div style={{ background: '#f5f5f5', padding: 16, borderRadius: 4 }}>
                  <pre style={{ margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
                    {JSON.stringify(submodData['ear.veraison.annotated-evidence'], null, 2)}
                  </pre>
                </div>
              )
            }
          ]}
        />
      </Card>
    );
  };

  return (
    <>
      <Card style={{ marginBottom: 16 }}>
        <Descriptions title="EAR Token 详情" bordered>
          <Descriptions.Item label="整体状态">
            <Tag color={
              result.trustStatus.ear?.overallStatus === 'valid' ? 'green' :
              result.trustStatus.ear?.overallStatus === 'warning' ? 'orange' :
              'red'
            }>
              {result.trustStatus.ear?.overallStatus}
            </Tag>
          </Descriptions.Item>
          <Descriptions.Item label="过期时间">
            {getTokenExpirationInfo(result)}
          </Descriptions.Item>
          <Descriptions.Item label="开发者">
            {claims['ear.verifier-id'].developer}
          </Descriptions.Item>
          <Descriptions.Item label="构建标识">
            {claims['ear.verifier-id'].build}
          </Descriptions.Item>
          <Descriptions.Item label="配置文件">
            {claims.eat_profile}
          </Descriptions.Item>
        </Descriptions>
      </Card>

      {Object.entries(claims.submods).map(([key, value]) => renderTrustVector(key, value))}
    </>
  );
};

const TokenDetails: React.FC<TokenDetailsProps> = ({ evaluationResult }) => {
  return (
    <div>
      <Space direction="vertical" style={{ width: '100%' }}>
        {evaluationResult.type === TokenType.Simple ? (
          <SimpleTokenDetails result={evaluationResult} />
        ) : (
          <EarTokenDetails result={evaluationResult} />
        )}
      </Space>
    </div>
  );
};

export default TokenDetails;