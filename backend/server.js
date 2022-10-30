const path = require("path")
const express = require("express")
const colors = require("colors")
const dotenv = require("dotenv").config()
const { errorHandler } = require("./middleware/errorMiddleware")
const connectDB = require("./config/db")
const PORT = process.env.PORT || 5000

//Connect to database
connectDB()

const app = express()

//bodyParser
app.use(express.json())
app.use(express.urlencoded({ extended: false }))

//Routes
app.use("/api/users", require("./routes/userRoutes"))
app.use("/api/tickets", require("./routes/ticketRoutes"))
app.use(errorHandler)

// Server Frontend
if (process.env.NODE_ENV === "production") {
  // Set build folder as static
  app.use(express.static(path.join(__dirname, "../frontend/build")))
  app.get("*", (req, res) =>
    res.sendFile(__dirname, "../frontend/build", "index.html")
  )
} else {
  app.get("/", (req, res) => {
    res.send("Hello")
  })
}

app.listen(PORT, () => console.log(`Server started on port: ${PORT}`))
