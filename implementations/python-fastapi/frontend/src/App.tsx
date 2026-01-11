import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { BackendProvider } from './contexts/BackendContext';
import Layout from './components/Layout';
import Dashboard from './pages/Dashboard';
import Challenges from './pages/Challenges';
import ChallengeDetail from './pages/ChallengeDetail';
import ApiConsole from './pages/ApiConsole';
import GraphQLConsole from './pages/GraphQLConsole';

function App() {
  return (
    <BackendProvider>
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<Layout />}>
            <Route index element={<Dashboard />} />
            <Route path="challenges" element={<Challenges />} />
            <Route path="challenge/:id" element={<ChallengeDetail />} />
            <Route path="console" element={<ApiConsole />} />
            <Route path="graphql" element={<GraphQLConsole />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </BackendProvider>
  );
}

export default App;
