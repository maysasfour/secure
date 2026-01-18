import React from 'react';
import { Outlet } from 'react-router-dom';
import { Container } from 'react-bootstrap';
import Navbar from './Navbar';
import Footer from './Footer';

const Layout = () => {
  return (
    <div className="d-flex flex-column min-vh-100">
      <Navbar />
      <main className="flex-grow-1 bg-light">
        <Container fluid className="py-4">
          <Outlet />
        </Container>
      </main>
      <Footer />
    </div>
  );
};

export default Layout;