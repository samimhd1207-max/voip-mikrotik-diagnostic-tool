import { Link } from 'react-router-dom';

function Home() {
  return (
    <main className="home-page">
      
      <div className="home-overlay" />
      <div className="home-content">
        <p className="home-brand">NETCOM GROUPE</p>

        <section className="home-hero">
          

          <h1>MikroTik &amp; VoIP Smart Diagnostic Tool</h1>
          <p>Analyse, configure and troubleshoot your network infrastructure </p>

          <div className="home-actions">
            <Link className="home-button home-button-primary" to="/diagnostic">
              Start Diagnostic
            </Link>
           
          </div>
        </section>
      </div>
    </main>
  );
}

export default Home;