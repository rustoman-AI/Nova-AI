import AppLayout from "./components/AppLayout";
import { EstopProvider } from "./components/EstopProvider";
import "./App.css";

function App() {
  return (
    <EstopProvider>
      <AppLayout />
    </EstopProvider>
  );
}

export default App;
