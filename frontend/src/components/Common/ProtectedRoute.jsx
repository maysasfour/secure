import { Navigate } from 'react-router-dom';

const ProtectedRoute = ({ children }) => {
    const isAuthenticated = localStorage.getItem('token'); // Basic check
    return isAuthenticated ? children : <Navigate path="/login" />;
};

export default ProtectedRoute;