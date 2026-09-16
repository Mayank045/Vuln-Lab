const Footer = () => {
    return (
        <div className='bg-slate-800 text-white flex flex-col justify-center items-center  w-full'>
            <div className="logo font-bold text-white text-2xl">
                <span className='text-green-500'> &lt;</span>
                <span>Vuln</span><span className='text-green-500'>Lab/&gt;</span>
            </div>
            <p className='text-center text-sm px-4 pb-4 max-w-2xl'>
                This application is intentionally vulnerable and is designed for educational and authorized security testing only.
                Run it locally or in an environment you own or have explicit permission to test.
            </p>
        </div>
    )
}

export default Footer
