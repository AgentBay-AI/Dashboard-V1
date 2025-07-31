import { apiClient } from '../lib/api';

async function testBackendConnection() {
  console.log('🔄 Testing backend connection...');
  
  try {
    // Test agent overview
    console.log('\n📊 Testing /agents/overview...');
    const overview = await apiClient.agents.getOverview();
    console.log('✅ Success:', overview);

    // Test agent registration
    console.log('\n🤖 Testing /agents/register...');
    const agent = await apiClient.agents.register({
      agent_id: 'test_agent_001',
      timestamp: new Date().toISOString(),
      metadata: {
        version: '1.0.0',
        environment: 'development',
        capabilities: ['chat', 'analysis']
      }
    });
    console.log('✅ Success:', agent);

    // Test LLM usage tracking
    console.log('\n📈 Testing /llm-usage...');
    const llmUsage = await apiClient.llm.trackUsage({
      timestamp: new Date().toISOString(),
      provider: 'openai',
      model: 'gpt-4',
      prompt_tokens: 150,
      completion_tokens: 75,
      total_tokens: 225,
      agent_id: 'test_agent_001'
    });
    console.log('✅ Success:', llmUsage);

    // Test dashboard overview
    console.log('\n🎯 Testing /dashboard/overview...');
    const dashboard = await apiClient.dashboard.getOverview();
    console.log('✅ Success:', dashboard);

    console.log('\n🎉 All tests passed! Backend is connected and working.');
  } catch (error: any) {
    console.error('\n❌ Error testing backend:', error.message);
    if (error.response) {
      console.error('Response:', error.response.data);
    }
  }
}

testBackendConnection(); 