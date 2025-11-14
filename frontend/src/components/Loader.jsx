function Loader() {
  return (
    <div className="flex flex-col items-center gap-4">
      <div className="relative">
        <div className="w-16 h-16 border-4 border-gray-700 border-t-blue-500 rounded-full animate-spin"></div>
      </div>
      <p className="text-gray-400 text-sm">Scanning domain...</p>
    </div>
  )
}

export default Loader

