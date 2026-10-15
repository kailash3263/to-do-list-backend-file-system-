const express = require('express');
const fs = require('fs');
const cors = require('cors');
const app = express(); 
app.use(cors());
app.use(express.json()); 
app.use(express.urlencoded({ extended: true }));
const PORT = 3000; 
app.post('/', (req, res) => {
  res.json({ received: req.body });
  fs.appendFileSync('data.txt',JSON.stringify(req.body)+"\n")
});
app.get('/all-task', (req, res) => {
     let data = fs.readFileSync('data.txt','utf-8');
     data = data.trim().split('\n');
     res.send(data);
});
app.delete('/delete/:idx', (req, res) => {
    let { idx } = req.params; 
    console.log(idx)
    let data = fs.readFileSync('data.txt','utf-8');
    data = data.trim().split('\n');
    data.splice(idx, 1); 
    fs.writeFileSync('data.txt',data.join('\n'));
});

app.put('/update/:idx', (req, res) => {
    let { idx } = req.params;
    let data = fs.readFileSync('data.txt', 'utf-8').trim().split('\n');
    data[idx] = JSON.stringify(req.body);
    fs.writeFileSync('data.txt', data.join('\n'));
    res.send('Task updated');
});

app.listen(PORT, () => {
    console.log(`Server is listening at http://localhost:${PORT}`);
});
