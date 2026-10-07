$(document).ready(function () {
//    $("#postReview").on("click", function () {
//        var commentInput = $("#reviewInput").val();
//        $.ajax({
//            type: 'POST',
//            url: 'csrf/review',
//            data: JSON.stringify({text: commentInput}),
//            contentType: "application/json",
//            dataType: 'json'
//        }).then(
//            function () {
//                getChallenges();
//                $("#commentInput").val('');
//            }
//        )
//    });

    getChallenges();

    function getChallenges() {
        $("#list").empty();
        $.get('csrf/review', function (result, status) {
            for (var i = 0; i < result.length; i++) {
                var li = $("<li>").addClass("comment");
                var pullLeft = $("<div>").addClass("pull-left");
                pullLeft.append($("<img>").addClass("avatar").attr("src", "images/avatar1.png").attr("alt", "avatar"));
                var body = $("<div>").addClass("comment-body");
                var heading = $("<div>").addClass("comment-heading");
                heading.append($("<h4>").addClass("user").text(result[i].user + " / " + result[i].stars + " stars"));
                heading.append($("<h5>").addClass("time").text(result[i].dateTime));
                body.append(heading);
                body.append($("<p>").text(result[i].text));
                li.append(pullLeft).append(body);
                $("#list").append(li);
            }

        });
    }
})
