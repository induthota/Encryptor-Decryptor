console.log("Let's write JavaScript");
let songs;

let currentSong = new Audio(); // Initialize without a source

function secondsToMinutesSeconds(seconds) {
    // Calculate whole minutes and remaining seconds
    var minutes = Math.floor(seconds / 60);
    var remainingSeconds = seconds % 60;

    // Format the output
    var formattedMinutes = String(minutes).padStart(2, '0');
    var formattedSeconds = String(Math.floor(remainingSeconds)).padStart(2, '0'); // Ensuring seconds is an integer

    return `${formattedMinutes}:${formattedSeconds}`;
}

async function getSongs() {
    let a = await fetch("http://127.0.0.1:3000/songs/");
    let response = await a.text();
    console.log(response);
    let div = document.createElement("div");
    div.innerHTML = response;
    let as = div.getElementsByTagName("a");
    let songs = [];
    for (let index = 0; index < as.length; index++) {
        const element = as[index];
        if (element.href.endsWith(".mp3")) {
            songs.push(element.href.split("/songs/")[1]);
        }
    }
    return songs;
}

const transformSongName = (name) => {
    return name.replace(/%20/g, " ").replace(/128-/g, "").replace(/128/g, "").replace(/Kbps\.mp3$/, ".mp3").replace(/ Yeh Jawaani Hai Deewani /g,"YJHD");
}

const playMusic = (track, pause = false) => {
    if (track) {
        currentSong.src = "/songs/" + track;
    }
    if (!pause && track) {
        currentSong.play();
        document.querySelector("#play").src = "pause.svg"; // Set play button to pause icon
    } else {
        document.querySelector("#play").src = "play.svg"; // Set play button to play icon
    }
    
    if (track) {
        document.querySelector(".songinfo").innerHTML = transformSongName(track);
        document.querySelector(".songtime").innerHTML = "00:00 / 00:00";
    } else {
        document.querySelector(".songinfo").innerHTML = "";
        document.querySelector(".songtime").innerHTML = "00:00 / 00:00";
    }
}

async function main() {
    songs = await getSongs();
    
    // Show all songs in the playlist
    let songUL = document.querySelector(".songList ul");
    for (const song of songs) {
        let displayName = transformSongName(song);
        songUL.innerHTML += `<li>
            <img class="invert" src="music.svg" alt="">
            <div class="info">
                <div>${displayName}</div>
                <div>Arijit Singh</div>
            </div>
            <div class="playnow">
                <span>Play Now</span>
                <img class="invert play-button" src="play.svg" alt="">
            </div>
        </li>`;
    }

    Array.from(document.querySelectorAll(".songList .play-button")).forEach(playButton => {
        playButton.addEventListener("click", (event) => {
            event.stopPropagation();
            let songDiv = playButton.closest("li").querySelector(".info div").innerHTML.trim();
            let track = songs.find(s => transformSongName(s) === songDiv);
            if (track) {
                playMusic(track);
            } else {
                console.error("Track not found for:", songDiv);
            }
        });
    });

    // Initialize with the first song in a paused state
    if (songs.length > 0) {
        playMusic(songs[0], true); // Pass true to pause the song initially
    }

    // Event listener for play/pause button
    document.querySelector("#play").addEventListener("click", () => {
        if (currentSong.paused && currentSong.src) {
            currentSong.play();
            document.querySelector("#play").src = "pause.svg";
        } else if (currentSong.src) {
            currentSong.pause();
            document.querySelector("#play").src = "play.svg";
        }
    });

    // Event listener for timeupdate event
    currentSong.addEventListener("timeupdate", () => {
        document.querySelector(".songtime").innerHTML =
            `${secondsToMinutesSeconds(currentSong.currentTime)}/${secondsToMinutesSeconds(currentSong.duration)}`;
        document.querySelector(".circle").style.left = (currentSong.currentTime / currentSong.duration) * 100 + "%";
    });

    // Event listener for previous button
    document.querySelector("#previous").addEventListener("click", () => {
        let currentIndex = songs.findIndex(song => song === currentSong.src.split("/").slice(-1)[0]);
        if (currentIndex > 0) {
            playMusic(songs[currentIndex - 1]);
        }
    });

    // Event listener for next button
    document.querySelector("#next").addEventListener("click", () => {
        currentSong.pause()
        let currentIndex = songs.findIndex(song => song === currentSong.src.split("/").slice(-1)[0]);
        if (currentIndex < songs.length ) {
            playMusic(songs[currentIndex + 1]);
        }
    });
}

main();

